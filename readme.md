# 🔐 Securosys HSM-Secured Bitcoin Transaction Broadcaster (Testnet)

This project enables the creation, signing, and broadcasting of **Bitcoin testnet** transactions using a **Securosys PrimusHSM** and a **Blockstream-compatible node API**. It securely stores and uses cryptographic keys inside a hardware security module (HSM) and builds fully-signed SegWit transactions for testnet.

---

## 🚀 Features

* ✅ SegWit (P2WPKH) transaction creation
* 🔐 HSM-based private key management and ECDSA signing
* 📡 Transaction broadcasting to Blockstream’s testnet node
* ⚖️ UTXO handling, fee control, and change output logic
* 🧪 Built for Bitcoin **testnet** network

---

## ⚙️ Setup Instructions

### 🔑 1. Register for Securosys CloudHSM

1. Go to [Securosys CloudHSM](https://cloud.securosys.com/)
2. Register and start a **90-day free trial**
5. Obtain your **API access token**

---

### 🌐 2. Register for Blockstream Dashboard

1. Go to [Blockstream Dashboard](https://dashboard.blockstream.info/)
2. Create an account and log in
3. Register a new application to get:

   * `NODE_CLIENT_ID`
   * `NODE_CLIENT_SECRET`
4. These will allow authenticated access to the testnet API and UTXO services

Sample Curl-requests: 

#### Get UTXOS for Address: 
```
ACCESS_TOKEN=

curl \
--request GET \
--location "https://enterprise.blockstream.info/testnet/api/address/tb1q680p9239dsze0jwfm8ccf0zaepu9nk5jansrns/utxo" \
--header "Authorization: Bearer ${ACCESS_TOKEN}"
```

---

### 📁 Environment Configuration

Create a `.env` file based on this template:

```env
# HSM Configuration
TSB_API_URL=https://sbx-rest-api.cloudshsm.com/v1/
TSB_KEY_LABEL=btc-test-key
TSB_ACCESS_TOKEN=your_securosys_bearer_access_token_here

# Blockstream Node API
NODE_AUTH_URL=https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token
NODE_API_URL=https://enterprise.blockstream.info/testnet/api
NODE_CLIENT_ID=your_blockstream_client_id
NODE_CLIENT_SECRET=your_blockstream_client_secret

# Transaction Settings
TO_ADDRESS_NEW=tb1qlj64u6fqutr0xue85kl55fx0gt4m4urun25p7q
```


## Fund your address

You can fund your address using: https://testnet-faucet.com/send.php or https://bitcoinfaucet.uo1.net/send.php
To send your testnet coins back, simply initiate a transaction from your testnet wallet to the following BTC address: tb1qlj64u6fqutr0xue85kl55fx0gt4m4urun25p7q

---

## 🧪 Requirements

* Python 3.8+
* Dependencies (install via `requirements.txt`):

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

Run the transaction script:

```bash
python main.py
```

or using streamlit:

```bash
streamlit run streamlit_app.py
```

This script will:

1. Retrieve or create a key from your HSM
2. Derive and verify your public key and sender address
3. Fetch UTXOs from Blockstream’s API
4. Build a signed SegWit transaction
5. (Optionally) Broadcast the signed transaction to the network

---

## 📦 Project Structure

```
project/
├── main.py                    # Main script
├── hsm/                       # HSM interface
│   ├── securosys_rest_api.py
│   └── helper.py
├── blockstream/               # Blockstream API handlers
│   └── blockstream_node.py
├── .env-template              # Example configuration
├── README.md
```

---

## 📌 Notes

* This project is for **testnet only** – not for production Bitcoin use.
* Ensure recipient address (`TO_ADDRESS_NEW`) is a valid **P2WPKH testnet** address (`tb1...`)
* Fees and amounts are configurable in `main.py`

---

## 🔒 Security

* Uses **Securosys HSM** for secure private key storage and signing
* No private key material leaves the HSM
* Secure API tokens required for both HSM and transaction broadcasting
