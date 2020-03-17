const crypto = require('crypto');

function intTo32BE(i) {
    const buf = new Buffer([0,0,0,0]);
    buf.writeInt32BE(i);
    return buf;
}

function x963kdf(key, algo, byteLength, sharedInfo) {
    let output = new Buffer([]);
    let outputlen = 0;
    let counter = 1;
    console.log('x963kdf: \n', key.toString('base64'), '\n', algo, '\n', byteLength, '\n', sharedInfo.toString('base64'));
    while (byteLength > outputlen) {
        const hasher = crypto
        .createHash(algo)
        .update(key)
        .update(intTo32BE(counter))
        if (sharedInfo) {
            hasher.update(sharedInfo);
        }
        const hashResult = hasher.digest();
        outputlen += hashResult.length;
        output = Buffer.concat([output, hashResult]);
        counter += 1;
    }
    console.log('X963KDF Result: ' + output.slice(0, byteLength).toString('base64'));
    return output.slice(0, byteLength)
}

module.exports = {x963kdf};