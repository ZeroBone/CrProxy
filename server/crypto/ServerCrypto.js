"use strict";

const nacl = require("./nacl/nacl");

const Nonce = require("./Nonce");

const MAGIC_NONCE = Buffer.from("8907a714cd1042e96daf7b9ad910c4cb2e34b2414fd5819f", "hex");

const MAGIC_KEY = Buffer.from("fb523187d9e4dcdb0a136e6a77a677de7a7983b9166eb1604f8f24aeecd750b3", "hex");

const PUBLIC_SERVER_KEY = Buffer.from("8cfd11687a20d616f0b7dc0ceed00ce12f5f95e2e100c9ff561b0c4117e6e44d", "hex");

class ServerCrypto {

    constructor() {}

    decrypt(message) {

        if (message.code === 10100) {

            return message.payload;

        }
        else if (message.code === 10101) {

            const publicKey = message.payload.slice(0, 32);

            const encrypted = message.payload.slice(32);

            // console.log(encrypted.length, encrypted);

            // const sharedKey = new Buffer(nacl.box.before(publicKey, Buffer.from("fb523187d9e4dcdb0a136e6a77a677de7a7983b9166eb1604f8f24aeecd750b3", "hex")));

            // console.log(sharedKey);

            const decrypted = nacl.box.open.after(
                encrypted,
                MAGIC_NONCE,
                MAGIC_KEY
            );

            console.log(decrypted);

            this.sNonce = new Nonce({
                bytes: decrypted.slice(24, 48)
            });

            return decrypted;

        }
        else {

            this.sNonce.increment(2);

            return Buffer.from(
                nacl.box.open.after(message.payload, this.sNonce.payload, new Uint8Array(32))
            );

        }

    }

    encrypt(code, payload, rNonce) {

        console.log("senc", code, payload, rNonce);

        if (code === 20103 || code === 20100) {

            return payload;

        }
        else if (code === 22194) {

            const nonce = new Nonce({
                publicKey: null,
                serverKey: Buffer.from("8cfd11687a20d616f0b7dc0ceed00ce12f5f95e2e100c9ff561b0c4117e6e44d", "hex"),
                payload: this.sNonce.payload
            });

            const data = new Uint8Array(Buffer.concat([
                new Uint8Array(24),
                new Uint8Array(32),
                payload
            ]));

            return nacl.box.after(
                data,
                nonce.payload,
                new Uint8Array(Buffer.from("fb523187d9e4dcdb0a136e6a77a677de7a7983b9166eb1604f8f24aeecd750b3", "hex"))
            );

        }
        else {

            rNonce.increment(2);

            return nacl.box.after(new Uint8Array(payload), rNonce.payload, new Uint8Array(32));

        }

    }

}

module.exports = ServerCrypto;