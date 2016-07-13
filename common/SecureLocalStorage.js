
/**
 * Constructor for secureStorage facade for application interaction with
 * localStorage or sessionStorage.
 * 
 * @param {String} encKey Hexadecimal string for encryption key, 256 bits.
 * @param {sessionStorage} storage Optional, defaults to localStorage.  sessionStorage may be 
 * specified if data does not need to presist outside of the current session.
 * For applications without persistence requirements, this improves security.
 * 
 * @returns {secureStorage}
 */
function secureStorage(encKey,storage) {
    if (storage == null) {
        storage = localStorage;
    }

    var hmac = new sjcl.misc.hmac(sjcl.codec.hex.toBits(encKey), sjcl.hash.sha256);

    this.encrypt = function(value) {
        return sjcl.encrypt(encKey, value);
    }

    this.setStorage = function (key,value) {
        var encryptedData = this.encrypt(value);
        var hashedKey = this.getHMAC(key);
        var hashAuthCodeKey = this.getHashAuthCodeKey(key)
        var hashAuthCode = this.getHMAC(value);
        storage[hashedKey] = encryptedData;
        storage[hashAuthCodeKey] = hashAuthCode;
    }
    
    this.getHashAuthCodeKey = function (key) {
        return this.getHMAC(key + 'com.hpe.demo.storage.protection');
    }
    
    this.decrypt = function (cypherText) {
        return sjcl.decrypt(encKey, cypherText);
    }

    this.getStorage = function (key) {
        var cypherText = storage[this.getHMAC(key)];
        var value = this.decrypt(cypherText);
        var hashAuthCodeKey = this.getHashAuthCodeKey(key)
        var hashAuthCode = this.getHMAC(value);
        var storedHashAuthCode = storage[hashAuthCodeKey];
        if (hashAuthCode !== storedHashAuthCode) {
            throw "HMAC mismatch.  Data corrupted.";
        }
        return value;
    }
 
    this.getHMAC = function (key) {
        bitArray = hmac.encrypt(key);
        return sjcl.codec.base64.fromBits(bitArray);  
    }
}