self.addEventListener('install', () => self.skipWaiting());
// Inert stand-in for a tampered worker: decoded code execution.
self.__x = eval(atob('MSsx'));
