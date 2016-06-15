
var encKey = '143ed16439a38147705da92a93ce6db98a2412c474c958785b26be186efbc15';

function encrypt(value) {
    return sjcl.encrypt(encKey, value);
}

function setLocalStorage(key,value) {
    var encryptedData = encrypt(value);
    var hashedKey = getHMAC(key);
    var hashAuthCodeKey = getHMAC(key + 'com.hp.demo.localstorage.protection');
    var hashAuthCode = getHMAC(value);
    localStorage[hashedKey] = encryptedData;
    localStorage[hashAuthCodeKey] = hashAuthCode;
}

function decrypt(cypherText) {
    return sjcl.decrypt(encKey, cypherText);
}

function getLocalStorage(key) {
    var cypherText = localStorage[getHMAC(key)];
    var value = decrypt(cypherText);
    var hashAuthCodeKey = getHMAC(key + 'com.hp.demo.localstorage.protection');
    var hashAuthCode = getHMAC(value);
    var storedHashAuthCode = localStorage[hashAuthCodeKey];
    if (hashAuthCode !== storedHashAuthCode) {
        throw "HMAC mismatch.  Data corrupted.";
    }
    return value;
}

function getHMAC(key) {
    var hmac = new sjcl.misc.hmac(sjcl.codec.hex.toBits(encKey), sjcl.hash.sha256);
    bitArray = hmac.encrypt(key);
    return sjcl.codec.base64.fromBits(bitArray);  
}