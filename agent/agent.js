import Java from "frida-java-bridge";

// Signal when Java bridge is loaded (non-blocking)
if (Java.available) {
    send('[+] Java bridge loaded (Java.available = true)');
} else {
    send('[!] Java bridge loaded but Java.available = false');
}

rpc.exports = {
    // Memory operations
    memoryListModules() {
        return Process.enumerateModules().map(m => ({
            name: m.name,
            base: m.base.toString(),
            size: m.size,
            path: m.path
        }));
    },

    memoryListExports(moduleName) {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return [];
        return mod.enumerateExports().map(e => ({
            name: e.name,
            address: e.address.toString(),
            type: e.type
        }));
    },

    memorySearch(pattern, isString) {
        const results = [];
        const searchPattern = isString
            ? pattern.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
            : pattern;

        Process.enumerateRanges('r--').forEach(range => {
            try {
                const matches = Memory.scanSync(range.base, range.size, searchPattern);
                matches.forEach(match => {
                    results.push({
                        address: match.address.toString(),
                        size: match.size
                    });
                });
            } catch (e) {}
        });
        return results.slice(0, 100);
    },

    memoryRead(address, size) {
        const addr = ptr(address);
        const hex = '0123456789abcdef';
        let out = '';
        for (let i = 0; i < size; i++) {
            const b = addr.add(i).readU8();
            out += hex[(b >> 4) & 0xf] + hex[b & 0xf];
        }
        return out;
    },

    // Android/Java hooking
    androidHookingGetClasses() {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const classes = [];
        Java.performNow(() => {
            Java.enumerateLoadedClasses({
                onMatch(className) {
                    classes.push(className);
                },
                onComplete() {}
            });
        });
        return classes;
    },

    androidHookingGetClassMethods(className) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const methods = [];
        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const declaredMethods = clazz.class.getDeclaredMethods();
                for (let i = 0; i < declaredMethods.length; i++) {
                    methods.push(declaredMethods[i].getName());
                }
            } catch (e) {
                methods.push("Error: " + e.message);
            }
        });
        return methods;
    },

    androidHookingEnumerate(pattern) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const results = [];
        const lowerPattern = pattern.toLowerCase();
        Java.performNow(() => {
            Java.enumerateLoadedClasses({
                onMatch(className) {
                    if (className.toLowerCase().includes(lowerPattern)) {
                        results.push(className);
                    }
                },
                onComplete() {}
            });
        });
        return results.slice(0, 100);
    },

    androidHookingWatch(pattern, dumpArgs, dumpBacktrace, dumpReturn) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const parts = pattern.split('!');
        const className = parts[0];
        const methodName = parts[1] || '*';

        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const declaredMethods = clazz.class.getDeclaredMethods();
                const methodNames = methodName === '*'
                    ? Array.from({ length: declaredMethods.length }, (_, i) => declaredMethods[i].getName())
                    : [methodName];

                methodNames.forEach(mName => {
                    const overloads = clazz[mName].overloads;
                    overloads.forEach(overload => {
                        overload.implementation = function(...args) {
                            let msg = '[HOOK] ' + className + '.' + mName + '(';
                            if (dumpArgs) {
                                const argStrs = [];
                                for (let i = 0; i < args.length; i++) {
                                    try {
                                        const arg = args[i];
                                        if (arg && arg.getClass) {
                                            const cls = arg.getClass().getName();
                                            if (cls === '[B') {
                                                const bytes = Java.array('byte', arg);
                                                const hex = Array.from(bytes).map(b =>
                                                    (b & 0xff).toString(16).padStart(2, '0')
                                                ).join('');
                                                argStrs.push('bytes[' + bytes.length + ']:' + hex.substring(0, 64));
                                            } else {
                                                argStrs.push(String(arg).substring(0, 100));
                                            }
                                        } else {
                                            argStrs.push(String(arg).substring(0, 100));
                                        }
                                    } catch (e) {
                                        argStrs.push('<error>');
                                    }
                                }
                                msg += argStrs.join(', ');
                            }
                            msg += ')';

                            if (dumpBacktrace) {
                                msg += '\n' + Java.use('android.util.Log')
                                    .getStackTraceString(Java.use('java.lang.Exception').$new());
                            }

                            const result = this[mName].apply(this, args);

                            if (dumpReturn && result !== undefined) {
                                try {
                                    if (result && result.getClass && result.getClass().getName() === '[B') {
                                        const bytes = Java.array('byte', result);
                                        const hex = Array.from(bytes).map(b =>
                                            (b & 0xff).toString(16).padStart(2, '0')
                                        ).join('');
                                        msg += ' => bytes[' + bytes.length + ']:' + hex.substring(0, 64);
                                    } else {
                                        msg += ' => ' + String(result).substring(0, 100);
                                    }
                                } catch (e) {
                                    msg += ' => <error>';
                                }
                            }

                            send(msg);
                            return result;
                        };
                    });
                });
                send('[+] Hooked: ' + pattern);
            } catch (e) {
                send('[-] Hook failed: ' + e.message);
            }
        });
    },

    androidSslpinningDisable() {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        Java.performNow(() => {
            const TrustManager = Java.registerClass({
                name: 'com.mcp.TrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted(chain, authType) {},
                    checkServerTrusted(chain, authType) {},
                    getAcceptedIssuers() { return []; }
                }
            });

            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const TrustManagers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);

            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function(km, tm, sr) {
                this.init(km, TrustManagers, sr);
            };

            send('[+] SSL pinning disabled');
        });
    },

    androidHookingGetCurrentActivity() {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        let activity = '';
        Java.performNow(() => {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const currentApp = ActivityThread.currentApplication();
            activity = currentApp.getClass().getName();
        });
        return activity;
    },

    // File operations
    fileLs(path) {
        if (!Java.available) {
            throw new Error("Java runtime not available for file operations");
        }
        const results = [];
        Java.performNow(() => {
            const File = Java.use('java.io.File');
            const dir = File.$new(path);
            const files = dir.listFiles();
            if (files) {
                for (let i = 0; i < files.length; i++) {
                    results.push({
                        name: files[i].getName(),
                        isDir: files[i].isDirectory(),
                        size: files[i].length(),
                        path: files[i].getAbsolutePath()
                    });
                }
            }
        });
        return results;
    },

    fileRead(path) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        let content = '';
        Java.performNow(() => {
            const FileInputStream = Java.use('java.io.FileInputStream');
            const BufferedReader = Java.use('java.io.BufferedReader');
            const InputStreamReader = Java.use('java.io.InputStreamReader');

            const fis = FileInputStream.$new(path);
            const reader = BufferedReader.$new(InputStreamReader.$new(fis));
            const lines = [];
            let line;
            while ((line = reader.readLine()) !== null) {
                lines.push(line);
            }
            reader.close();
            content = lines.join('\n');
        });
        return content;
    },

    fileDownload(path) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        let bytes = [];
        Java.performNow(() => {
            const File = Java.use('java.io.File');
            const FileInputStream = Java.use('java.io.FileInputStream');

            const file = File.$new(path);
            const size = file.length();
            const fis = FileInputStream.$new(file);
            const buffer = Java.array('byte', new Array(size).fill(0));
            fis.read(buffer);
            fis.close();
            bytes = Array.from(buffer);
        });
        return bytes;
    },

    // Run arbitrary code within Java.performNow context
    // Code should set `result` variable to return a value
    runJava(code) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        let result = null;
        let error = null;
        Java.performNow(() => {
            try {
                // Execute the code - it can use Java.use(), Java.choose(), etc.
                // and should assign to `result` to return a value
                result = eval(code);
            } catch(e) {
                error = e.message;
            }
        });
        if (error) {
            throw new Error(error);
        }
        return result;
    },

    // Dump all methods, fields, and constructors of a Java class
    dumpClass(className) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const result = { methods: [], fields: [], constructors: [] };
        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const jClass = clazz.class;

                // Methods
                const methods = jClass.getDeclaredMethods();
                for (let i = 0; i < methods.length; i++) {
                    result.methods.push(methods[i].toString());
                }

                // Fields
                const fields = jClass.getDeclaredFields();
                for (let i = 0; i < fields.length; i++) {
                    result.fields.push(fields[i].toString());
                }

                // Constructors
                const ctors = jClass.getDeclaredConstructors();
                for (let i = 0; i < ctors.length; i++) {
                    result.constructors.push(ctors[i].toString());
                }
            } catch (e) {
                result.error = e.message;
            }
        });
        return result;
    },

    // Search Java heap for instances of a class
    heapSearch(className, maxResults) {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const results = [];
        const limit = maxResults || 10;
        Java.performNow(() => {
            try {
                Java.choose(className, {
                    onMatch(instance) {
                        if (results.length < limit) {
                            const info = { handle: instance.$h || instance.toString() };
                            try {
                                info.toString = instance.toString();
                            } catch (e) {}
                            try {
                                info.class = instance.getClass().getName();
                            } catch (e) {}
                            results.push(info);
                        }
                    },
                    onComplete() {}
                });
            } catch (e) {
                results.push({ error: e.message });
            }
        });
        return { instances: results };
    },

    // List Android Keystore entries
    keystoreList() {
        if (!Java.available) {
            throw new Error("Java runtime not available");
        }
        const entries = [];
        let error = null;
        Java.performNow(() => {
            try {
                const KeyStore = Java.use('java.security.KeyStore');
                const ks = KeyStore.getInstance('AndroidKeyStore');
                ks.load(null);
                const aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    const alias = aliases.nextElement();
                    entries.push(alias.toString());
                }
            } catch (e) {
                error = e.message;
            }
        });
        if (error) {
            return { keystore_entries: [], error: error };
        }
        return { keystore_entries: entries };
    }
};

send('[+] frida-mcp agent loaded');
