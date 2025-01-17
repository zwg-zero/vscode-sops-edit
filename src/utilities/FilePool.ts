import { TextDocument, Uri, window } from "vscode";
import { readFileSync, unlinkSync } from "fs";
import { EditorContext } from "./EditorContext";
import * as f from "./functions";

type ExtendedTempFile = {
	tempFile: Uri,
    originalFile: Uri,
	content: string
};

export class FilePool {
    // pool of excluded file paths, existing of:
    //   - TMP files created by this extension
    //   - SOPS-encrypted files marked for direct editing
    private _excludedFilePaths: string[];
    
    // pool of open TMP file details, each item containing:
    //  - original file path
	//  - temp file path
	//  - temp file content (to track file changes)
    private _tempFiles: ExtendedTempFile[];

    public constructor() {
        this._excludedFilePaths = [];
        this._tempFiles = [];
    }

    public async openTextDocumentListener(textDocument:TextDocument) : Promise<void> {
        if (f.getSettingOnlyUseButtons()) {
            return;
        }
        // on open document: if it is a sops encrypted file: close and open a decrypted copy instead
        const encryptedFile = Uri.file(f.gitFix(textDocument.fileName));
    
        // only apply if this is a non-excluded sops encrypted file
        const isSopsEncryptedFile: boolean = await f.isSopsEncrypted(encryptedFile);
        const isExcluded: boolean = this._excludedFilePaths.includes(encryptedFile.path);
        if (!isSopsEncryptedFile || isExcluded ) {
            return;
        }

        const isOpenInPlainTextEditor: boolean = await f.isOpenedInPlainTextEditor(encryptedFile, true);
        if (!isOpenInPlainTextEditor) {
            return;
        }
        
        await this._editDecryptedTmpCopy(encryptedFile);
    }
    
    public closeTextDocumentListener(textDocument:TextDocument) : void {
        if (f.getSettingOnlyUseButtons()) {
            return;
        }
        // 	- remove document from excluded files (if present)
        // 	- if it is a tmp version of SOPS encrypted file: remove tempFiles entry, delete
        const closedFile = Uri.file(f.gitFix(textDocument.fileName));
        this._removeExcludedPathsEntry(closedFile.path);
        this._removeTempFilesEntryAndDelete(closedFile);
    }
    
    public saveTextDocumentListener(textDocument:TextDocument) : void {
        EditorContext.set(window.activeTextEditor, this);
        if (f.getSettingOnlyUseButtons()) {
            return;
        }
        // save and encrypt when it is a tmp file
        const savedFile = Uri.file(f.gitFix(textDocument.fileName));
        const content = textDocument.getText().trim();
        void this._copyEncryptSaveContentsIfTempFile(savedFile, content);
    }

    public editDirectly(files:Uri[]) : void {
        if (files.length === 0) {
            f.noFileSelectedErrormessage();
            return;
        }
        
        const directEditFile = files[0];
        this._excludedFilePaths.push(directEditFile.path);
        void f.openFile(directEditFile);
    }

    public containsTempFile(tempFile:Uri) : boolean {
        return this._getTempFileIndex(tempFile) !== -1;
    }

    private async _editDecryptedTmpCopy(encryptedFile: Uri) : Promise<void> {
        const tempFile = f.getTempUri(encryptedFile);
    
        const index = this._getTempFileIndex(tempFile);
        if (index !== -1) {
            return;
        }

        this._addTempFilesEntry(tempFile, encryptedFile);
        this._excludedFilePaths.push(tempFile.path);

        //await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        const out = await f.decryptToTmpFileV2(encryptedFile, tempFile);

        if (out.stderr) {
            // on error: cancel
            this._removeTempFilesEntryAndDelete(tempFile);
            this._removeExcludedPathsEntry(tempFile.path);
            return;
        }

        // update tempFiles entry with file content
        this._tempFiles[this._getTempFileIndex(tempFile)].content = readFileSync(tempFile.fsPath, 'utf-8');

        await f.openFile(tempFile);
    }

    private _addTempFilesEntry(tempFile: Uri, encryptedFile:Uri) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index !== -1) {
            return;
        }

        this._tempFiles.push({
            tempFile:tempFile, 
            originalFile: encryptedFile,
            content: ''
        });
    }

    private _removeTempFilesEntryAndDelete(tempFile:Uri) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index === -1) {
            return;
        }

        this._tempFiles.splice(index, 1);
        unlinkSync(tempFile.fsPath);
    }

    private _removeExcludedPathsEntry(path:string) {
        if (this._excludedFilePaths.includes(path)) {
            this._excludedFilePaths.splice(this._excludedFilePaths.indexOf(path), 1);
        }
    }

    private _copyEncryptSaveContentsIfTempFile(tempFile:Uri, tempFileContent: string) : void {
        const index = this._getTempFileIndex(tempFile);
        if (index === -1 || this._tempFiles[index].content === tempFileContent) {
            return;
        }

        const extTempFile = this._tempFiles[index];
        extTempFile.content = tempFileContent;
        void f.copyEncrypt(extTempFile.tempFile, extTempFile.originalFile);
    }

    private _getTempFileIndex(tempFile:Uri) : number {
        return this._tempFiles.findIndex(t => t.tempFile.path === tempFile.path);
    }
}