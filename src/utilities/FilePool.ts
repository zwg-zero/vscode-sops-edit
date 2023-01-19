import * as fs from "fs";
import * as vscode from "vscode";
import * as c from "./constants";
import * as f from "./functions";

type ExtendedTempFile = {
	tempFile: vscode.Uri,
    originalFile: vscode.Uri,
	content: string
};

export class FilePool {
    // pool of excluded file paths, existing of:
    //   - TMP files created by this extension
    //   - SOPS-encrypted files marked for direct editing
    private _excludedFilePaths: string[];
    
    // pool of open TMP file details, each item containing:
	//  - temp file path
	//  - temp file content (to track file changes)
	//  - encryption terminal
    private _tempFiles: ExtendedTempFile[];

    private _encryptionTerminal: vscode.Terminal|undefined;

    public constructor() {
        this._excludedFilePaths = [];
        this._tempFiles = [];
        this._encryptionTerminal = undefined;
    }

    public async openTextDocumentListener(textDocument:vscode.TextDocument) : Promise<void> {
        // on open document: if it is a sops encrypted file: close and open a decrypted copy instead
        const encryptedFile = vscode.Uri.file(f.gitFix(textDocument.fileName));
    
        // only apply if this is a non-excluded sops encrypted file
        const isSopsEncrypted: boolean = await f.isSopsEncrypted(encryptedFile);
        const isExcluded: boolean = this._excludedFilePaths.includes(encryptedFile.path);
        if (!isSopsEncrypted || isExcluded ) {
            return;
        }
    
        await this._editDecryptedTmpCopy(encryptedFile);
    }
    
    public closeTextDocumentListener(textDocument:vscode.TextDocument) : void {
        // 	- remove document from excluded files (if present)
        // 	- if it is a tmp version of SOPS encrypted file: remove tempFiles entry, delete
        const closedFile = vscode.Uri.file(f.gitFix(textDocument.fileName));
        this._removeExcludedPathsEntry(closedFile.path);
        this._removeTempFilesEntryAndDelete(closedFile);
    }
    
    public saveTextDocumentListener(textDocument:vscode.TextDocument) : void {
        // save and encrypt when it is a tmp file
        const savedFile = vscode.Uri.file(f.gitFix(textDocument.fileName));
        const content = textDocument.getText().trim();
        this._copyEncryptSaveContentsIfTempFile(savedFile, content);
    }

    public editDirectly(files:vscode.Uri[]) : void {
        if (files.length === 0) {
            void vscode.window.showErrorMessage('Cannot edit file directly: no file selected');
            return;
        } 
        
        const directEditFile = files[0];
        this._excludedFilePaths.push(directEditFile.path);
        void f.openFile(directEditFile);
    }

    private async _editDecryptedTmpCopy(encryptedFile: vscode.Uri) : Promise<void> {
        const tempFile = f.getTempUri(encryptedFile);
    
        const index = this._getTempFileIndex(tempFile);
        if (index !== -1) {
            return;
        }

        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        this._addTempFilesEntry(tempFile, encryptedFile);
        this._excludedFilePaths.push(tempFile.path);
        await f.decryptWithProgressBar(encryptedFile, tempFile);

        // update tempFiles entry with file content
        this._tempFiles[this._getTempFileIndex(tempFile)].content = fs.readFileSync(tempFile.fsPath, 'utf-8');

        await f.openFile(tempFile);
    }

    private _addTempFilesEntry(tempFile: vscode.Uri, encryptedFile:vscode.Uri) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index !== -1) {
            return;
        }

        this._tempFiles.push({
            tempFile:tempFile, 
            originalFile: encryptedFile,
            content: ''
        });

        // open terminal if first tmp file is opened
        if (!this._encryptionTerminal) {
            this._encryptionTerminal = vscode.window.createTerminal(c.terminalEncryptName);
        }
    }

    private _removeTempFilesEntryAndDelete(tempFile:vscode.Uri) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index === -1) {
            return;
        }

        this._tempFiles.splice(index, 1);
        fs.unlinkSync(tempFile.fsPath);

        // exit terminal if the last tmp file was closed
        if (this._tempFiles.length === 0 && this._encryptionTerminal) {
            f.executeInTerminal(['exit'], this._encryptionTerminal);
            this._encryptionTerminal = undefined;
        }
    }

    private _removeExcludedPathsEntry(path:string) {
        if (this._excludedFilePaths.includes(path)) {
            this._excludedFilePaths.splice(this._excludedFilePaths.indexOf(path), 1);
        }
    }

    private _copyEncryptSaveContentsIfTempFile(tempFile:vscode.Uri, tempFileContent: string) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index !== -1 && this._tempFiles[index].content !== tempFileContent && this._encryptionTerminal) {
            this._tempFiles[index].content = tempFileContent;
            f.copyEncrypt(this._tempFiles[index], this._encryptionTerminal);
        }
    }

    private _getTempFileIndex(tempFile:vscode.Uri) : number {
        return this._tempFiles.findIndex(t => t.tempFile.path === tempFile.path);
    }
}