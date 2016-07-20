
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

    /**
     * Encrypt the value.
     * @param {Object} value Object to encrypt.
     * @returns {sjcl.json.encrypt} JSON representation of the encrypted object.
     */
    this.encrypt = function(value) {
        return sjcl.encrypt(encKey, value);
    }

    /**
     * Set the specified key to the specified value.  Also stores a
     * HMAC-SHA256 hash of the value which is used to detect possible
     * tampering.
     * 
     * @param {type} key Key to associate with the value.
     * @param {type} value Value to store.
     * @returns {undefined}
     */
    this.setStorage = function (key,value) {
        var encryptedData = this.encrypt(value);
        var hashedKey = this.getHMAC(key);
        var hashAuthCodeKey = this.getHashAuthCodeKey(key)
        var hashAuthCode = this.getHMAC(value);
        storage[hashedKey] = encryptedData;
        storage[hashAuthCodeKey] = hashAuthCode;
    }

    /**
     * Key with a suffix that is used as the key for the HMAC-SHA code to
     * validate that a value is untampered with.
     * @param {type} key Key used to store the value.
     * @returns {String} Key that will store the HMAC-SHA256 code.
     */
    this.getHashAuthCodeKey = function (key) {
        return this.getHMAC(key + 'com.hpe.demo.storage.protection');
    }

    /**
     * Return the decrypted value.
     * @param {type} cypherText From encrypt function.
     * @returns {sjcl.json.decrypt} Decrypted value.
     */
    this.decrypt = function (cypherText) {
        return sjcl.decrypt(encKey, cypherText);
    }

    /**
     * Get, decrypt, and verify the value in storage.
     * @param {type} key Key that this value was set under.
     * @returns {sjcl.json.decrypt} Decrypted and validated values.
     * @throws {String} If HMAC mismatches (value was altered after being stored).
     */
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

    /**
     * Get HMAC code for the specified key or value.
     * @param {type} key Key or value to obtain code.
     * @returns {String} Base64 encoded string of the computed code.
     */
    this.getHMAC = function (key) {
        bitArray = hmac.encrypt(key);
        return sjcl.codec.base64.fromBits(bitArray);  
    }
}