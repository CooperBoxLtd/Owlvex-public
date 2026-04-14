import * as vscode from 'vscode';

let secretStorage: vscode.SecretStorage | undefined;

export function initializeSecretStorage(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export function getSecretStorage(): vscode.SecretStorage | undefined {
    return secretStorage;
}
