import { Uri, Progress, window, ProgressLocation, workspace, Tab, TabInputText } from "vscode";
import { readFileSync, copyFileSync, promises as fspromises } from "fs";
import { EditorContext } from './EditorContext';
import { FilePool } from "./FilePool";
import { parse as yamlParse, parseAllDocuments as yamlParseAllDocuments } from "yaml";
import {parse as iniParse} from 'ini';
import { STSClient, AssumeRoleCommand, AssumeRoleCommandInput} from '@aws-sdk/client-sts';
import { exec } from "node:child_process";
import * as c from "./constants";
import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'fs';
import * as readline from 'node:readline';
import * as fs_extra from 'fs-extra';
import * as vscode from 'vscode';

// const DEBUG_NAMESPACE = '@signageos/vscode-sops';
// const debug = vscode.window.createOutputChannel(DEBUG_NAMESPACE);
// debug.show();

type AwsConfig = {
	name?: string,
	roleArn?: string,
	sourceProfile?: string,
	mfaSerial?: string,
	roleSessionName?: string
};
type AwsCredential = {
	name?: string,
	awsAccessKeyId?: string,
	awsSecretAccessKey?: string,
	awsSessionToken?: string,
	expiration?: string
};

class AwsCredNotExistError extends Error {
	// eslint-disable-next-line @typescript-eslint/explicit-member-accessibility
	constructor(message: string) {
		super(message);
		this.name = 'AwsCredNotExistError';
	}
}
class AwsCredInvalidError extends Error {
	// eslint-disable-next-line @typescript-eslint/explicit-member-accessibility
	constructor(message: string) {
		super(message);
		this.name = 'AwsCredInvalidError';
	}
}
class AwsCredExpiredError extends Error {
	// eslint-disable-next-line @typescript-eslint/explicit-member-accessibility
	constructor(message: string) {
		super(message);
		this.name = 'AwsCredExpiredError';
	}
}

type EncryptedWithAwsProfile = {
	isEncrypted: boolean,
	awsProfile?: string,
};

type PatternSet = [string, string[]];
type PatternSetV2 = [string, string[][]];

type PathDetails = {
	fileName:string, 
	parent:Uri, 
	filePureName:string, 
	extension:string
};
type ProgressBar = Progress<{
    message?: string | undefined;
    increment?: number | undefined;
}>;
type Answer = {
	stdout:string,
	stderr:string
};

export function decryptCommand(files:Uri[]|Uri, filePool: FilePool) : void {
	const file = _getSingleUriFromInput(files);
	if (!file) {
		return;
	}
	void _decryptInPlaceV2(file)
		.then(() => EditorContext.set(window.activeTextEditor, filePool))
		.catch(() => {return;});

}

export function encryptCommand(files:Uri[]|Uri, filePool: FilePool) : void {
	const file = _getSingleUriFromInput(files);
	if (!file) {
		return;
	}

	void _encryptInPlaceWithProgressBarV2(file).then(() => EditorContext.set(window.activeTextEditor, filePool));
}

function _getParentUri(file:Uri) : Uri {
	return Uri.joinPath(file, '..');
}

function _dissectUri(file:Uri) : PathDetails {
	const fName = file.path.split('/').pop() ?? '';

	return {
		fileName: fName,
		parent: _getParentUri(file),
		filePureName: fName.replace(c.getFileExtensionRegExp, ''),
		extension: fName.split('.').pop() ?? ''
	};
}

export function getTempUri(file:Uri) : Uri {
	const fd = _dissectUri(file);
	const tempFileName = `${fd.filePureName}.${_getSettingTempFilePreExtension()}.${fd.extension}`;
	return Uri.joinPath(fd.parent, tempFileName);
}

export async function openFile(file:Uri) : Promise<void> {
	const doc = await workspace.openTextDocument(file);
	await window.showTextDocument(doc);
}

export function gitFix(path:string) : string {
	return path.replace(c.gitExtensionRegExp, '');
}

type AwsAuthEnv = {
	// eslint-disable-next-line @typescript-eslint/naming-convention
	AWS_SHARED_CREDENTIALS_FILE?: string,
	// eslint-disable-next-line @typescript-eslint/naming-convention
	AWS_CONFIG_FILE?: string,
};

function _getAwsAuthOptions(awsProfile: string) : AwsAuthEnv{
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const awsAuthEnvVars: AwsAuthEnv = {};
	awsAuthEnvVars['AWS_SHARED_CREDENTIALS_FILE'] = path.join(os.homedir(), '.aws', `credentials_${awsProfile}`);
	awsAuthEnvVars['AWS_CONFIG_FILE'] = path.join(os.homedir(), '.aws', `config_${awsProfile}`);
	return awsAuthEnvVars;
}

// throw:
// AwsCredNotExistError,AwsCredInvalidError,AwsCredExpiredError
async function _checkAwsCredential(awsProfile: string) {
	const awsCredentialPath = path.join(os.homedir(), '.aws', `credentials_${awsProfile}`);
	if (! fs_extra.existsSync(awsCredentialPath)) {
			throw new AwsCredNotExistError(`the aws credential file not exists under the ${awsCredentialPath}`);
	}
	const awsCred: AwsCredential = await new Promise((resolve, reject) => {
			const result: AwsCredential = {};
			const dataStream = fs.createReadStream(awsCredentialPath);
			const lineReader = readline.createInterface({
					input: dataStream
			});
			dataStream.once('error', err => reject(err));
			lineReader.on('line', (line) => {
					const lineS = line.toString();
					if ( lineS === `[${awsProfile}]`) {
							result.name = awsProfile;
					} else {
							const value = lineS.substring(lineS.indexOf('=')+1, lineS.length).trim();
							if (lineS.startsWith("aws_access_key_id")) {
									result.awsAccessKeyId = value;
							} else if (lineS.startsWith("aws_secret_access_key")) {
									result.awsSecretAccessKey = value;
							} else if (lineS.startsWith("aws_session_token")) {
									result.awsSessionToken = value;
							} else if (lineS.startsWith("expiration")) {
									result.expiration = value;
							}
					}
			});
			lineReader.on('close', ()=>{
					resolve(result);
			});
	});
	if (!awsCred.name) {
			throw new AwsCredInvalidError(`not find the profile name with ${awsProfile}`);
	}
	// check if the credential doesn't expired
	const nowDate = new Date();
	if (!awsCred.expiration) {
		throw new AwsCredExpiredError(`no expiration data in config file`);
	}
	const expireDate = Date.parse(awsCred.expiration);
	// expire date in 5 min, will need to get new aws session token 
	const diffDate = expireDate - nowDate.getTime();
	if (diffDate < 60 * 5 * 100) {
			throw new AwsCredExpiredError(`the aws session token will be expired in ${diffDate}`);
	}
}

async function _getAwsConfig(awsProfile: string): Promise<AwsConfig> {
	const awsConfigPath = path.join(os.homedir(), ".aws", "config");
	if (! fs_extra.existsSync(awsConfigPath)) {
			throw new Error(`the aws config file not exists under the ${awsConfigPath}`);
	}
	const awsConfig: AwsConfig = await new Promise((resolve, reject) => {
		const result: AwsConfig = {};
		let isNeeded = false;
		const dataStream = fs.createReadStream(awsConfigPath);
		const lineReader = readline.createInterface({
				input: dataStream
		});
		dataStream.once('error', err => reject(err));
		lineReader.on('line', (line) => {
			if ( line.toString() === `[profile ${awsProfile}]`) {
					isNeeded = true;
			} else if (line.toString().startsWith(`[`)) {
					if (isNeeded) {
							// already read the lines
							lineReader.close();
					}
			}
			if (isNeeded) {
				const lineS = line.toString();
				const value = lineS.substring(lineS.indexOf('=')+1, lineS.length).trim();
				if (lineS.startsWith("role_arn")) {
						result.roleArn = value;
				} else if (lineS.startsWith("source_profile")) {
						result.sourceProfile = value;
				} else if (lineS.startsWith("mfa_serial")) {
						result.mfaSerial = value;
				} else if (lineS.startsWith("role_session_name")) {
						result.roleSessionName = value;
				}
			}
		});
		lineReader.on('close', ()=>{
			result.name = awsProfile;
			resolve(result);
		});
	});
	return awsConfig;
}

async function _getAwsSessionToken(awsConfig: AwsConfig, mfaCode: string) {
	const client = new STSClient();
	const input: AssumeRoleCommandInput = { // AssumeRoleRequest
		// eslint-disable-next-line @typescript-eslint/naming-convention
		RoleArn: awsConfig.roleArn, // required
		// eslint-disable-next-line @typescript-eslint/naming-convention
		RoleSessionName: "sops-aws-assume-role-session", // required
		// eslint-disable-next-line @typescript-eslint/naming-convention
		DurationSeconds: 3600,
		// eslint-disable-next-line @typescript-eslint/naming-convention
		SerialNumber: awsConfig.mfaSerial,
		// eslint-disable-next-line @typescript-eslint/naming-convention
		TokenCode: mfaCode
	};
	const command = new AssumeRoleCommand(input);
	const response = await client.send(command);
	if (!response.Credentials) {
	throw new Error("no credentials in the reponse of aws assume role");
	}
	if (!response.Credentials.AccessKeyId || !response.Credentials.SecretAccessKey || !response.Credentials.SessionToken || !response.Credentials.Expiration) {
	throw new Error("no accessid or accesskey or session toke in credentials in the reponse of aws assume role");
	}
	const awsCred: AwsCredential = {
	name: awsConfig.name,
	awsAccessKeyId: response.Credentials.AccessKeyId,
	awsSecretAccessKey: response.Credentials.SecretAccessKey,
	awsSessionToken: response.Credentials.SessionToken,
	expiration: response.Credentials.Expiration.toISOString()
 };
	return awsCred;
}

async function _writeAwsCredential(awsCred: AwsCredential) : Promise<void> {
	// debug.appendLine("in _writeAwsCredential");
	const filePath = path.join(os.homedir(), '.aws', `credentials_${awsCred.name}`);
	const content = [
			`[${awsCred.name}]`,
			`aws_access_key_id = ${awsCred.awsAccessKeyId}`,
			`aws_secret_access_key = ${awsCred.awsSecretAccessKey}`,
			`aws_session_token = ${awsCred.awsSessionToken}`,
			`expiration = ${awsCred.expiration}`
	];
	await fs.promises.writeFile(filePath, content.join('\n')+'\n');
}

async function _writeAwsConfig(awsCred: AwsCredential) : Promise<void> {
	// debug.appendLine("in _writeAwsConfig");
	const filePath = path.join(os.homedir(), '.aws', `config_${awsCred.name}`);
	await fs.promises.writeFile(filePath, "");
}

async function _insureAwsAuth(awsProfile: string) {
	// debug.appendLine("in _insureAwsAuth");
	try {
		await _checkAwsCredential(awsProfile);
	} catch (error) {
		// debug.appendLine(`${error}`);
		if (error instanceof AwsCredExpiredError || error instanceof AwsCredInvalidError || error instanceof AwsCredNotExistError) {
			// generate new aws credential file
			const config = await _getAwsConfig(awsProfile);
			// debug.appendLine(`${config.name}`);
			// get mfa token from vscode input
			const mfaCode = await vscode.window.showInputBox({title: "AWS MFA Code", placeHolder: "Input MFA code"});
			if (mfaCode === undefined || mfaCode === '') {
					throw new Error("no mfa code input");

			}
			const cred = await _getAwsSessionToken(config, mfaCode);
			// debug.appendLine(`${cred.name}, ${cred.expiration}`);
			await _writeAwsConfig(cred);
			await _writeAwsCredential(cred);
		} else {
				throw error;
		}
	}
}

function _executeShellCommand(command:string, cwd:Uri, customEnv: AwsAuthEnv, errorMessage:string) : Answer {
	let out = {stdout:'', stderr:''};
	exec(command, {cwd:cwd.fsPath, env: {...process.env, ...customEnv}}, (_, stdout, stderr) => {
		out = {stdout:stdout, stderr:stderr};
	});
	if (out.stderr) {
		void window.showErrorMessage(`${errorMessage}: ${out.stderr}`);
	}
	return out;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function _executeShellCommandWithProgressBar(command:string, cwd:Uri, customEnv: any, progressTitle:string, errorMessage:string) : Promise<Answer> {
	// run a shell command and show a moving progress bar in the mean time
	let out:Answer = {stdout:'', stderr:''};
	await window.withProgress(
		{location: ProgressLocation.Notification, cancellable: false, title: progressTitle}, 
		async (progress) => {
			// create progress bar at 0%
			progress.report({  increment: 0 });
			// pointer with 'done' status which will be updated by the command once finished, 
			// and monitored by the progress bar to close once updated 
			const progressDetails = { isDone: false };
			// execute shell command 
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-explicit-any
			exec(command, {cwd: cwd.fsPath, env: {...process.env, ...customEnv}}, (_, stdout, stderr) => {
				// once finished: update 'done' status, close progress bar
				out = {stdout:stdout, stderr:stderr};
				progress.report({ increment: 100 });
				progressDetails.isDone = true;
				return;
			});
			// update progress bar while not done
			await _fakeProgressUpdate(progress, progressDetails);			
		}
	);
	if (out.stderr) {
		void window.showErrorMessage(`${errorMessage}: ${out.stderr}`);
	}
	return out;
}

async function _delay(ms: number) {
    return new Promise( resolve => setTimeout(resolve, ms) );
}

async function _fakeProgressUpdate(progressBar:ProgressBar, executionStatus: { isDone:boolean }) : Promise<void> {
	// add increments to given progressbar every 50 ms, until external execution is done
	let rem = 100;
	while(!executionStatus.isDone) {
		await _delay(50);
		const inc = Math.max(Math.floor(rem/20), 1);
		rem -= inc;
		if (rem > 0) {
			progressBar.report({ increment: inc});
		}
	}
	return;
}

function _getSingleUriFromInput(input:Uri[]|Uri) : Uri|void {
	let file:Uri;
	if (Array.isArray(input)) {
		if (input.length === 0) {
			noFileSelectedErrormessage();
			return;
		}
		file = input[0];
	} else {
		file = input;
	}

	return file;
}

export function noFileSelectedErrormessage() : void {
	void window.showErrorMessage('Cannot edit file directly: no file selected');
}

// async function _decryptInPlace(encryptedFile:Uri) : Promise<Answer> {
// 	const enc = _dissectUri(encryptedFile);
// 	const decryptionCommand = c.decryptInPlaceCommand.replace(c.fileString, enc.fileName);
// 	const progressTitle = `Decrypting ${enc.fileName} ...`;
// 	const errorMessage = `Error decrypting ${enc.fileName}`;
// 	return await _executeShellCommandWithProgressBar(decryptionCommand, enc.parent, {}, progressTitle, errorMessage);
// }

async function _decryptInPlaceV2(encryptedFile:Uri) : Promise<Answer> {
	const isAwsEncypted = isEncryptedV2(encryptedFile);
	// prepare for aws mfa auth
	let awsEnv: AwsAuthEnv = {};
	if (isAwsEncypted.awsProfile) {
		await _insureAwsAuth(isAwsEncypted.awsProfile);
		awsEnv = _getAwsAuthOptions(isAwsEncypted.awsProfile);
	}
	const enc = _dissectUri(encryptedFile);
	const decryptionCommand = c.decryptInPlaceCommand.replace(c.fileString, enc.fileName);
	const progressTitle = `Decrypting ${enc.fileName} ...`;
	const errorMessage = `Error decrypting ${enc.fileName}`;
	return await _executeShellCommandWithProgressBar(decryptionCommand, enc.parent, awsEnv, progressTitle, errorMessage);
}

export async function decryptToTmpFile(encryptedFile:Uri, tempFile:Uri) : Promise<Answer> {
	const enc = _dissectUri(encryptedFile);
	const temp = _dissectUri(tempFile);
	const decryptionCommand = c.decryptToTmpCommand.replace(c.fileString, enc.fileName).replace(c.tempFileString, temp.fileName);
	const progressTitle = `Decrypting ${enc.fileName} ...`;
	const errorMessage = `Error decrypting ${enc.fileName}`;
	return await _executeShellCommandWithProgressBar(decryptionCommand, enc.parent, {}, progressTitle, errorMessage);
}

export async function decryptToTmpFileV2(encryptedFile:Uri, tempFile:Uri) : Promise<Answer> {
	//debug.appendLine("in decryptToTmpFileV2");
	const isAwsEncypted = isEncryptedV2(encryptedFile);
	// prepare for aws mfa auth
	let awsEnv: AwsAuthEnv = {};
	if (isAwsEncypted.awsProfile) {
		// debug.appendLine(`awsprofile: ${isAwsEncypted.awsProfile}`);
		await _insureAwsAuth(isAwsEncypted.awsProfile).catch((error)=> {return {stdout: "", stderr: `${error}`};});
		awsEnv = _getAwsAuthOptions(isAwsEncypted.awsProfile);
	}
	const enc = _dissectUri(encryptedFile);
	const temp = _dissectUri(tempFile);
	const decryptionCommand = c.decryptToTmpCommand.replace(c.fileString, enc.fileName).replace(c.tempFileString, temp.fileName);
	const progressTitle = `Decrypting ${enc.fileName} ...`;
	const errorMessage = `Error decrypting ${enc.fileName}`;
	// debug.appendLine(`${awsEnv.AWS_CONFIG_FILE}, ${awsEnv.AWS_SHARED_CREDENTIALS_FILE}`);
	return await _executeShellCommandWithProgressBar(decryptionCommand, enc.parent, awsEnv, progressTitle, errorMessage);
}

export async function copyEncrypt(tempFile:Uri, originalFile:Uri) : Promise<Answer> {
	void copyFileSync(tempFile.fsPath, originalFile.fsPath);
	return await _encryptInPlaceV2(originalFile);	
}

// function _encryptInPlace(file:Uri) : Answer {
// 	const fileDetails = _dissectUri(file);
// 	const command = c.encryptCommand.replace(c.fileString, fileDetails.fileName);
// 	const errorMessage = `Error encrypting ${fileDetails.fileName}`;
// 	return _executeShellCommand(command, fileDetails.parent, {}, errorMessage);
// }

async function _encryptInPlaceV2(file:Uri) : Promise<Answer> {
	const isAwsEncypted = await _isEncryptableV2(file);
	// prepare for aws mfa auth
	let awsEnv: AwsAuthEnv = {};
	if (isAwsEncypted.awsProfile) {
		await _insureAwsAuth(isAwsEncypted.awsProfile);
		awsEnv = _getAwsAuthOptions(isAwsEncypted.awsProfile);
	}
	const fileDetails = _dissectUri(file);
	const command = c.encryptCommand.replace(c.fileString, fileDetails.fileName);
	const errorMessage = `Error encrypting ${fileDetails.fileName}`;
	return _executeShellCommand(command, fileDetails.parent, awsEnv, errorMessage);
}

// async function _encryptInPlaceWithProgressBar(file:Uri): Promise<Answer> {
// 	const fileDetails = _dissectUri(file);
// 	const command = c.encryptCommand.replace(c.fileString, fileDetails.fileName);
// 	const progressTitle = `Encrypting ${fileDetails.fileName} ...`;
// 	const errorMessage = `Error encrypting ${fileDetails.fileName}`;
// 	return await _executeShellCommandWithProgressBar(command, fileDetails.parent, {}, progressTitle, errorMessage);
// }

async function _encryptInPlaceWithProgressBarV2(file:Uri): Promise<Answer> {
	const isAwsEncypted = await _isEncryptableV2(file);
	// prepare for aws mfa auth
	let awsEnv: AwsAuthEnv = {};
	if (isAwsEncypted.awsProfile) {
		await _insureAwsAuth(isAwsEncypted.awsProfile);
		awsEnv = _getAwsAuthOptions(isAwsEncypted.awsProfile);
	}	
	const fileDetails = _dissectUri(file);
	const command = c.encryptCommand.replace(c.fileString, fileDetails.fileName);
	const progressTitle = `Encrypting ${fileDetails.fileName} ...`;
	const errorMessage = `Error encrypting ${fileDetails.fileName}`;
	return await _executeShellCommandWithProgressBar(command, fileDetails.parent, awsEnv, progressTitle, errorMessage);
}

export async function isOpenedInPlainTextEditor(file:Uri, closeIfOpened = false) : Promise<boolean> {
	const tabs: Tab[] = window.tabGroups.all.map(tg => tg.tabs).flat();
	const index = tabs.findIndex(tab => tab.input instanceof TabInputText && tab.input.uri.path === file.path);
	if (index !== -1 && closeIfOpened) {
		await window.tabGroups.close(tabs[index]);
	}
	return index !== -1;
}

export async function isTooLargeToConsider(file:Uri) : Promise<boolean> {
	const stats = await fspromises.stat(file.fsPath);
	const fileSize = stats.size;
	return fileSize > (1024 * 1024);
}

export async function getSopsFiles() : Promise<Uri[]> {
	return await workspace.findFiles(c.sopsYamlGlob);
}

export async function isEncryptable(file:Uri) : Promise<boolean> {
	// go through all regexes in all .sops.yaml files, combine them with 
	// the .sops.yaml file location, and return if given file path matches any
	const sopsFiles =  await getSopsFiles();
	for (const sf of sopsFiles) {
		const pr: PatternSet = _getSopsPatternsFromFile(sf);
		for (const re of pr[1]) {
			if (new RegExp(`${pr[0]}/.*${re}`).test(file.path)) {
				return true;
			}
		}
	}
	return false;
}

async function _isEncryptableV2(file:Uri) : Promise<EncryptedWithAwsProfile> {
	// go through all regexes in all .sops.yaml files, combine them with 
	// the .sops.yaml file location, and return if given file path matches any
	const sopsFiles =  await getSopsFiles();
	for (const sf of sopsFiles) {
		const pr: PatternSetV2 = _getSopsPatternsFromFileV2(sf);
		for (const re of pr[1]) {
			if (new RegExp(`${pr[0]}/.*${re[0]}`).test(file.path)) {
				return {isEncrypted: true, awsProfile: re[1]};
			}
		}
	}
	return {isEncrypted: false};
}

export function isEncrypted(file:Uri) : boolean {
	// check if file is encrypted by parsing as ini, env or yaml and checking for sops property
	const contentString: string = readFileSync(file.fsPath, 'utf-8');
	const extension = getUriFileExtension(file);

	if (extension === 'ini') {
		return isEncryptedIniFile(contentString);
	} else if (extension === 'env') {
		return isEncryptedEnvFile(contentString);
	}
		
	return isEncryptedYamlFile(contentString);
}

export function isEncryptedV2(file:Uri) : EncryptedWithAwsProfile {
	// check if file is encrypted by parsing as ini, env or yaml and checking for sops property
	const contentString: string = readFileSync(file.fsPath, 'utf-8');
	const extension = getUriFileExtension(file);

	if (extension === 'ini') {
		return _isEncryptedIniFileV2(contentString);
	}		
	return _isEncryptedYamlFileV2(contentString);
}

export async function isSopsEncrypted(file:Uri) : Promise<boolean> {
	// check if file is encryptable (i.e. if it matches any regex in any .sops.yaml file),
	// and if so, check if it is indeed encrypted
	if (!await isEncryptable(file)) {
		return false;
	}

	if (await isTooLargeToConsider(file)) {
		return false;
	}

	return isEncrypted(file);
}

export function isEncryptedYamlFile(contentString:string) : boolean {
	try {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		const content = yamlParse(contentString);
		return Object.prototype.hasOwnProperty.call(content, "sops");
	} catch (error) {
		try {
			const documents = yamlParseAllDocuments(contentString);
			for (const doc of documents) {
				// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
				const content = yamlParse(doc.toString());
				return Object.prototype.hasOwnProperty.call(content, "sops");
			}
		} catch (error) {
			return false;
		}
	}
	return false;
}

function _isEncryptedYamlFileV2(contentString:string) : EncryptedWithAwsProfile{
	try {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		const content = yamlParse(contentString);
		if (Object.prototype.hasOwnProperty.call(content, "sops")) {
			// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
			return {isEncrypted: true, awsProfile: content?.sops?.kms[0]?.aws_profile};
		}
	} catch (error) {
		try {
			const documents = yamlParseAllDocuments(contentString);
			for (const doc of documents) {
				// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
				const content = yamlParse(doc.toString());
				if (Object.prototype.hasOwnProperty.call(content, "sops")) {
					// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
					return {isEncrypted: true, awsProfile: content?.sops?.kms[0]?.aws_profile};
				}
			}
		} catch (error) {
			return {isEncrypted: false};
		}
	}
	return {isEncrypted: false};
}

export function isEncryptedEnvFile(contentString: string) : boolean {
	return contentString.match(/(^|\r?\n)sops_version=/) !== null;
}

export function isEncryptedIniFile(contentString:string) : boolean {
	try {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
		const content = iniParse(contentString);
		return Object.prototype.hasOwnProperty.call(content, "sops");
	} catch (error) {
		return false;
	}
}

function _isEncryptedIniFileV2(contentString:string) : EncryptedWithAwsProfile{
	try {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
		const content = iniParse(contentString);
		
		if (Object.prototype.hasOwnProperty.call(content, "sops")) {
			// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
			return  {isEncrypted: true, awsProfile: content.sops?.ksm[0]?.aws_profile};
		} else {
			return  {isEncrypted: false};
		}
	} catch (error) {
		return {isEncrypted: false};
	}
}

export function getUriFileExtension(file:Uri) : string {
	return file.path.split('.').pop() ?? '';
}

function _getSopsPatternsFromFile(sopsFile:Uri) : PatternSet {
	// open .sops.yaml file, extract path_regex patterns, combine with file location to return a PatternSet
	const contentString: string = readFileSync(sopsFile.fsPath, 'utf-8');
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
	const content = yamlParse(contentString);
	
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-explicit-any
	const fileRegexes: string[] = content.creation_rules.map((cr:any) => cr.path_regex);
	return [_getParentUri(sopsFile).path, fileRegexes];
}

function _getSopsPatternsFromFileV2(sopsFile:Uri) : PatternSetV2 {
	// open .sops.yaml file, extract path_regex patterns, combine with file location to return a PatternSet
	const contentString: string = readFileSync(sopsFile.fsPath, 'utf-8');
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
	const content = yamlParse(contentString);
	
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-explicit-any
	const fileRegexes: string[][] = content.creation_rules.map((cr:any) => [cr.path_regex, cr.aws_profile]);
	return [_getParentUri(sopsFile).path, fileRegexes];
}
function _getSettingTempFilePreExtension() : string {
	return workspace.getConfiguration().get<string>('sops-edit.tempFilePreExtension') ?? 'tmp';
}

export function getSettingOnlyUseButtons() : boolean {
	return workspace.getConfiguration().get<boolean>('sops-edit.onlyUseButtons') ?? false;
}