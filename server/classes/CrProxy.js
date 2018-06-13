"use strict";

const net = require("net");

const Packetizer = require("./Packetizer");

const ClientCrypto = require("../crypto/ClientCrypto");
const ServerCrypto = require("../crypto/ServerCrypto");

class CrProxy {

    constructor() {

        this.client = null;

        this.server = null;

        this.clientPacketizer = new Packetizer();

        this.serverPacketizer = new Packetizer();

        this._setupListeners();

        this.server.listen(9339);

        this.clientCrypto = new ClientCrypto();

        this.serverCrypto = new ServerCrypto();

    }

    _setupListeners() {

        this.server = new net.Server((socket) => {

            console.log("[PROXY]: New client connecting...");

            if (this.client !== null) {

                console.warn("2 or more clients connecting...");

                return;

            }

            /**
             * Server logic.
             */

            this.client = new net.Socket();

            this.client.connect(9339, "game.clashroyaleapp.com");

            this.client.on("data", (chunk) => {

                // socket.write(chunk);

                // console.log("msg from server");

                // a message came from clash royale server

                this.serverPacketizer.packetize(chunk, (packet) => {

                    const message = {
                        code: packet.readUInt16BE(0),
                        length: packet.readUIntBE(2, 3),
                        payload: packet.slice(7, packet.length)
                    };

                    const decrypted = this.clientCrypto.decrypt(message);

                    console.log("[SERVER]: " + message.code + " len: " + message.length);

                    console.log(decrypted.toString());

                    const data = this.serverCrypto.encrypt(message.code, decrypted, this.clientCrypto.rnonce);

                    const header = Buffer.alloc(7);

                    header.writeUInt16BE(message.code, 0);

                    header.writeUIntBE(Buffer.from(data).length, 2, 3);

                    header.writeUInt16BE(0, 5); // was 0 or 4

                    socket.write(Buffer.concat([
                        header,
                        Buffer.from(data)
                    ]));

                });

            });

            /**
             * Client logic.
             */

            socket.on("data", (chunk) => {

                // a message came from cr client

                // console.log("msg from client");

                // this.client.write(chunk);

                this.clientPacketizer.packetize(chunk, (packet) => {

                    const message = {
                        code: packet.readUInt16BE(0),
                        length: packet.readUIntBE(2, 3),
                        payload: packet.slice(7, packet.length)
                    };

                    console.log("[CLIENT]: " + message.code + " len: " + message.length);

                    const decrypted = this.serverCrypto.decrypt(message);

                    console.log(decrypted);

                    const data = this.clientCrypto.encrypt(message.code, message.payload);

                    const header = Buffer.alloc(7);

                    header.writeUInt16BE(message.code, 0);

                    header.writeUIntBE(data.length, 2, 3);

                    header.writeUInt16BE(message.code === 10101 ? 4 : 0, 5);

                    this.client.write(Buffer.concat([
                        header,
                        Buffer.from(data)
                    ]));

                });

            });

        });

    }

}

module.exports = CrProxy;
