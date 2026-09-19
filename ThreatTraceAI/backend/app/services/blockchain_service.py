"""
Chain-of-custody: hash the finalized case and write the hash to Polygon Amoy testnet.
Only the hash + case_id + timestamp go on-chain – never the email content.
"""
from typing import Optional, Dict
from app.config import get_settings
from app.utils.hashing import sha256_of_dict

settings = get_settings()

# Minimal ABI for a simple logger contract:
# function logCaseHash(bytes32 caseHash, string caseId) external
LOGGER_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "caseHash", "type": "bytes32"},
            {"internalType": "string", "name": "caseId", "type": "string"}
        ],
        "name": "logCaseHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

def prepare_case_hash(case: dict) -> str:
    """Canonical hash of the forensic record."""
    # Only include stable forensic fields
    subset = {
        "case_id": case.get("case_id"),
        "subject": case.get("subject"),
        "sender": case.get("sender"),
        "risk_score": case.get("risk_score"),
        "risk_level": case.get("risk_level"),
        "urls": case.get("urls"),
        "domains": case.get("domains"),
        "ips": case.get("ips"),
        "recommendation": case.get("recommendation"),
        "created_at": str(case.get("created_at"))
    }
    return sha256_of_dict(subset)

async def log_case_to_chain(case: dict) -> Dict:
    """
    Attempts to write the hash on-chain.
    If PRIVATE_KEY or CONTRACT_ADDRESS are missing, returns a simulated response
    so the rest of the demo still works.
    """
    case_hash = prepare_case_hash(case)
    case_id = case.get("case_id", "unknown")

    if not settings.PRIVATE_KEY or not settings.CONTRACT_ADDRESS:
        return {
            "success": False,
            "simulated": True,
            "case_hash": case_hash,
            "message": "Blockchain credentials not configured – hash computed but not written to chain. Set PRIVATE_KEY + CONTRACT_ADDRESS in .env for live testnet write.",
            "explorer_hint": "https://amoy.polygonscan.com"
        }

    try:
        from web3 import Web3
        from eth_account import Account

        w3 = Web3(Web3.HTTPProvider(settings.POLYGON_RPC_URL))
        if not w3.is_connected():
            return {
                "success": False,
                "case_hash": case_hash,
                "message": "Could not connect to Polygon Amoy RPC"
            }

        account = Account.from_key(settings.PRIVATE_KEY)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS),
            abi=LOGGER_ABI
        )

        # Prepare transaction
        nonce = w3.eth.get_transaction_count(account.address)
        tx = contract.functions.logCaseHash(
            bytes.fromhex(case_hash),
            case_id
        ).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 200000,
            "maxFeePerGas": w3.to_wei("50", "gwei"),
            "maxPriorityFeePerGas": w3.to_wei("30", "gwei"),
            "chainId": settings.CHAIN_ID
        })

        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "success": True,
            "simulated": False,
            "case_hash": case_hash,
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "explorer": f"https://amoy.polygonscan.com/tx/{receipt.transactionHash.hex()}"
        }
    except Exception as e:
        return {
            "success": False,
            "case_hash": case_hash,
            "message": f"Blockchain write failed: {str(e)[:200]}"
        }
