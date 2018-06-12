"use strict";

// const nacl = require("tweetnacl");
const Nonce = require("./nonce");

const config = require("../config");

const nacl = require("./nacl/nacl");

class ClientCrypto {

    constructor() {}

    encrypt(code, payload) {

        if (code === 10100) {

            return payload;

        }
        else if (code === 10101) {

            this.snonce = new Nonce();

            this.nonce = new Nonce({
                publicKey: this.keys.publicKey,
                serverKey: this.serverKey
            });

            this.sharedKey = nacl.box.before(this.serverKey, this.keys.secretKey);

            let crypted = nacl.box.after(Buffer.concat([this.sessionKey, this.snonce.payload, payload]), this.nonce.payload, this.sharedKey);

            // was: return Buffer.concat([this.keys.publicKey, Buffer.from(crypted)])
            return Buffer.concat([Buffer.from(this.keys.publicKey), Buffer.from(crypted)]);

        }

        this.snonce.increment(2);

        return nacl.box.after(payload, this.snonce.payload, this.sharedKey);

    }

    decrypt(message) {

        switch (message.code) {
            // was case: 20100
            case 20100:
                // handshakeOk

                this.serverKey = Buffer.from(config.crypto.serverKey, "hex");

                this.keys = nacl.box.keyPair();

                const length = message.payload.readInt32BE();

                this.sessionKey = message.payload.slice(4, 4 + length);

                console.log("Session key:", this.sessionKey.toString("hex"));

                return message.payload;

            case 20103:
                // loginFailed

                return message.payload;
            // was case: 20104
            // was case 22280:
            case 22194:
                // loginOk

                const nonce = this.nonce = new Nonce({
                    publicKey: this.keys.publicKey,
                    serverKey: this.serverKey,
                    bytes: this.snonce.payload
                });

                const decrypted = nacl.box.open.after(message.payload, nonce.payload, this.sharedKey);

                if (!decrypted) {

                    throw new Error("Failed to decrypt LoginOk and retrieve rNonce and the sharedKey from it.");

                }

                this.sharedKey = Buffer.from(decrypted.slice(24, 56));

                console.log("sharedKey: ", this.sharedKey.toString("hex"));

                this.rnonce = new Nonce({
                    bytes: decrypted.slice(0, 24)
                });

                return decrypted.slice(56);

            default:

                this.rnonce.increment(2);


                return nacl.box.open.after(message.payload, this.rnonce.payload, this.sharedKey);

        }
    }

}


module.exports = ClientCrypto;