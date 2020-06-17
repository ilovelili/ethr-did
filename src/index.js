// ethjs vs web3
// https://medium.com/l4-media/announcing-ethers-js-a-web3-alternative-6f134fdd06f3#:~:text=One%20major%20difference%20between%20ethers,and%20read%20the%20ethereum%20blockchain.
import HttpProvider from "ethjs-provider-http";
import Eth from "ethjs-query";
import EthContract from "ethjs-contract";
import DidRegistryContract from "ethr-did-resolver/contracts/ethr-did-registry.json";
import { SimpleSigner, toEthereumAddress } from "did-jwt";
import { Buffer } from "buffer";
import { REGISTRY, stringToBytes32, delegateTypes } from "ethr-did-resolver";
const EC = require("elliptic").ec;
const secp256k1 = new EC("secp256k1");
const { Secp256k1VerificationKey2018 } = delegateTypes;

function configureProvider(conf = {}) {
	if (conf.provider) return conf.provider;
	if (conf.web3) return conf.web3.currentProvider;
	return new HttpProvider(conf.rpcUrl || "https://mainnet.infura.io/ethr-did");
}

function attributeToHex(key, value) {
	if (Buffer.isBuffer(value)) {
		return `0x${value.toString("hex")}`;
	}

	const match = key.match(/^did\/(pub|auth|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
	if (match) {
		const encoding = match[6];
		// TODO add support for base58
		if (encoding === "base64") {
			return `0x${Buffer.from(value, "base64").toString("hex")}`;
		}
	}

	if (value.match(/^0x[0-9a-fA-F]*$/)) {
		return value;
	}

	return `0x${Buffer.from(value).toString("hex")}`;
}

export default class EthrDID {
	constructor(conf = {}) {
		const provider = configureProvider(conf);
		const eth = new Eth(provider);
		const contract = new EthContract(eth);
		// https://github.com/uport-project/ethr-did-registry (default REGISTRY is '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b')
		const registryAddress = conf.registry || REGISTRY;
		// abi of https://raw.githubusercontent.com/uport-project/ethr-did-registry/develop/build/contracts/EthereumDIDRegistry.json
		const DidReg = contract(DidRegistryContract);
		// https://github.com/ethjs/ethjs-contract/blob/HEAD/docs/user-guide.md
		this.registry = DidReg.at(registryAddress);
		this.address = conf.address;
		if (!this.address) throw new Error("No address is set for EthrDid");
		this.did = `did:ethr:${this.address}`;

		if (conf.signer) {
			this.signer = conf.signer;
		} else if (conf.privateKey) {
			this.signer = SimpleSigner(conf.privateKey);
		}
	}

	static createKeyPair() {
		const kp = secp256k1.genKeyPair();
		const publicKey = kp.getPublic("hex");
		const privateKey = kp.getPrivate("hex");
		const address = toEthereumAddress(publicKey);
		return { address, privateKey };
	}

	// interface implementations of EIP-1056
	async lookupOwner(cache = true) {
		if (cache && this.owner) return this.owner;
		const result = await this.registry.identityOwner(this.address);
		return result["0"];
	}

	async changeOwner(newOwner) {
		const owner = await this.lookupOwner();
		const txHash = await this.registry.changeOwner(this.address, newOwner, {
			from: owner,
		});
		this.owner = newOwner;
		return txHash;
	}

	async addDelegate(delegate, options = {}) {
		const delegateType = options.delegateType || Secp256k1VerificationKey2018;
		const expiresIn = options.expiresIn || 24 * 60 * 60;
		const owner = await this.lookupOwner();
		// { from: owner } default tx defined here?
		return this.registry.addDelegate(this.address, delegateType, delegate, expiresIn, { from: owner });
	}

	async revokeDelegate(delegate, delegateType = Secp256k1VerificationKey2018) {
		const owner = await this.lookupOwner();
		return this.registry.revokeDelegate(this.address, delegateType, delegate, { from: owner });
	}

	async setAttribute(key, value, expiresIn = 86400, gasLimit) {
		const owner = await this.lookupOwner();
		return this.registry.setAttribute(this.address, stringToBytes32(key), attributeToHex(key, value), expiresIn, {
			from: owner,
			gas: gasLimit,
		});
	}

	async revokeAttribute(key, value, gasLimit) {
		const owner = await this.lookupOwner();
		return this.registry.revokeAttribute(this.address, stringToBytes32(key), attributeToHex(key, value), {
			from: owner,
			gas: gasLimit,
		});
	}
}
