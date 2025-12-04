from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from datetime import timedelta, datetime
from PIL import Image
import pytesseract
from web3 import Web3
from django.http import HttpResponse
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from .models import Block, TrackingLog, Institute

# --- CONFIGURATION ---
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ==========================================
# BLOCKCHAIN CONNECTION
# ==========================================
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# *** PASTE YOUR CONTRACT ADDRESS HERE ***
contract_address = '0xFE8A0eE17b3F5D443CDa75747336F680240098E6' 

# *** PASTE YOUR ABI HERE ***
contract_abi = [
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "string",
				"name": "serial",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "denomination",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "time",
				"type": "uint256"
			}
		],
		"name": "NoteMinted",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "admin",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_serial",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_denom",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_meta",
				"type": "string"
			}
		],
		"name": "mintNote",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"name": "notes",
		"outputs": [
			{
				"internalType": "string",
				"name": "serialNumber",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "denomination",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "metadataPath",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "address",
				"name": "minter",
				"type": "address"
			},
			{
				"internalType": "bool",
				"name": "exists",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_serial",
				"type": "string"
			}
		],
		"name": "verifyNote",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]

contract = web3.eth.contract(address=contract_address, abi=contract_abi)
admin_account = web3.eth.accounts[0] 

# ==========================================
# 0. HELPER FUNCTIONS
# ==========================================
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for: return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

# ==========================================
# 1. AUTHENTICATION
# ==========================================
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        if pass1 != pass2:
            messages.error(request, "❌ Passwords do not match!")
            return redirect('register')
        if User.objects.filter(username=username).exists():
            messages.error(request, "❌ Username already taken!")
            return redirect('register')
        my_user = User.objects.create_user(username, '', pass1)
        my_user.save()
        messages.success(request, "✅ Account Created! Please Login.")
        return redirect('login')
    return render(request, 'register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        pass1 = request.POST.get('password')
        selected_role = request.POST.get('role') 
        user = authenticate(request, username=username, password=pass1)
        if user is not None:
            if selected_role == 'admin' and not (user.is_superuser or user.is_staff):
                messages.error(request, "❌ Access Denied: You are not an Admin!")
                return redirect('login')
            login(request, user)
            if selected_role == 'admin': return redirect('admin_dashboard')
            else: return redirect('user_dashboard')
        else:
            messages.error(request, "❌ Invalid Username or Password")
            return redirect('login')
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    messages.info(request, "Logged out successfully.")
    return redirect('login')



# ==========================================
# 2. ADMIN DASHBOARD (Duplicate Prevention)
# ==========================================
def admin_dashboard(request):
    context = {}
    context['chain'] = Block.objects.all().order_by('-index')
    context['institutes'] = Institute.objects.all().order_by('-registration_date')
    
    # Ethereum Stats
    try:
        latest_block_number = web3.eth.block_number
        gas_price = web3.eth.gas_price
        eth_blocks = []
        for i in range(latest_block_number, max(-1, latest_block_number - 5), -1):
            block = web3.eth.get_block(i)
            eth_blocks.append({
                'number': block['number'],
                'hash': block['hash'].hex(),
                'timestamp': datetime.fromtimestamp(block['timestamp']),
                'gas_used': block['gasUsed'],
                'tx_count': len(block['transactions'])
            })
        context['eth_blocks'] = eth_blocks
        context['network_stats'] = {
            'block_height': latest_block_number,
            'gas_price': web3.from_wei(gas_price, 'gwei'),
            'status': "ONLINE 🟢"
        }
    except Exception as e:
        context['network_stats'] = {'status': f"OFFLINE 🔴 ({str(e)})"}

    if request.method == 'POST':
        
        # --- REGISTER INSTITUTE ---
        if 'register_btn' in request.POST:
            inst_name = request.POST.get('institute_name')
            license_id = request.POST.get('license_id')
            
            if Institute.objects.filter(license_id=license_id).exists():
                context['message'] = f"❌ Error: License ID '{license_id}' already registered."
                context['msg_type'] = "error"
            else:
                Institute.objects.create(institute_name=inst_name, license_id=license_id)
                context['message'] = f"✅ Success! '{inst_name}' registered securely."
                context['msg_type'] = "success"
                context['institutes'] = Institute.objects.all().order_by('-registration_date')

        # --- MINT CURRENCY (SECURE + DUPLICATE CHECK) ---
        elif 'mint_btn' in request.POST:
            
            # 1. CHECK CREDENTIALS
            authority = request.POST.get('issuing_authority')
            security_key = request.POST.get('mint_password')

            if authority != "RBI":
                context['message'] = "⛔ ACCESS DENIED: Only Reserve Bank of India can mint currency."
                context['msg_type'] = "error"
            
            elif security_key != "RBI2025":
                context['message'] = "🔒 SECURITY ALERT: Invalid Security Key! Access Denied."
                context['msg_type'] = "error"
            
            else:
                # 2. PROCEED IF AUTHORIZED
                if request.FILES.get('admin_image'):
                    uploaded_file = request.FILES['admin_image']
                    fs = FileSystemStorage()
                    filename = fs.save(uploaded_file.name, uploaded_file)
                    file_path = fs.path(filename)
                    manual_value = request.POST.get('manual_value')

                    try:
                        # Auto-Scan Serial
                        img = Image.open(file_path).convert('L')
                        text = pytesseract.image_to_string(img, config='--psm 6')
                        serial = ''.join(e for e in text if e.isalnum())
                        
                        if len(serial) < 3: # Retry
                             text = pytesseract.image_to_string(img, config='--psm 11')
                             serial = ''.join(e for e in text if e.isalnum())

                        if len(serial) < 3:
                             context['message'] = "❌ OCR Failed: Serial unreadable."
                             context['msg_type'] = "error"
                        else:
                            # 3. BLOCKCHAIN CHECK (The Fix)
                            # Before spending gas, check if it exists locally first (Optional optimization)
                            if Block.objects.filter(serial_no=serial).exists():
                                context['message'] = f"⛔ DUPLICATE DETECTED: Note '{serial}' is already minted!"
                                context['msg_type'] = "error"
                            else:
                                try:
                                    # Attempt to Mint on Ethereum
                                    tx_hash = contract.functions.mintNote(
                                        serial, manual_value, filename
                                    ).transact({'from': admin_account})
                                    
                                    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
                                    
                                    # If successful, save to Local DB
                                    last_block = Block.objects.last()
                                    new_index = (last_block.index + 1) if last_block else 1
                                    eth_hash = receipt.transactionHash.hex()
                                    
                                    Block.objects.create(
                                        index=new_index,
                                        serial_no=serial,
                                        denomination=manual_value,
                                        previous_hash="ETH-CHAIN", 
                                        hash=eth_hash,             
                                        meta_data_path=filename
                                    )

                                    context['message'] = f"✅ MINTED! Serial: {serial} | Value: ₹{manual_value}"
                                    context['msg_type'] = "success"
                                    context['chain'] = Block.objects.all().order_by('-index')
                                    
                                except ValueError as ve:
                                    # CATCH SOLIDITY REVERT ERROR
                                    error_str = str(ve)
                                    if "Serial number already exists" in error_str:
                                        context['message'] = f"⛔ BLOCKCHAIN REJECTED: Serial '{serial}' already exists on-chain!"
                                    else:
                                        context['message'] = f"Blockchain Error: {ve}"
                                    context['msg_type'] = "error"

                    except Exception as e:
                        context['message'] = f"Error: {str(e)}"
                        context['msg_type'] = "error"
                else:
                    context['message'] = "❌ Error: Please upload an image."
                    context['msg_type'] = "error"

        # --- TRACKING ---
        elif 'track_btn' in request.POST:
            target_serial = request.POST.get('target_serial')
            logs = TrackingLog.objects.filter(serial_number=target_serial).order_by('-timestamp')
            if logs.exists():
                context['tracking_logs'] = logs
                context['searched_serial'] = target_serial
                context['msg_type'] = "success"
            else:
                context['msg_type'] = "error"
                context['message'] = f"No history found."

    return render(request, 'admin.html', context)

# ==========================================
# 3. USER DASHBOARD (Ethereum Read)
# ==========================================
def user_dashboard(request):
    context = {}
    if request.method == 'POST' and request.FILES.get('image'):
        uploaded_file = request.FILES['image']
        fs = FileSystemStorage()
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(filename)
        
        try:
            img = Image.open(file_path).convert('L')
            user_serial = ''.join(e for e in pytesseract.image_to_string(img, config='--psm 6') if e.isalnum())
            if len(user_serial) < 3:
                user_serial = ''.join(e for e in pytesseract.image_to_string(img, config='--psm 11') if e.isalnum())

            suspicious_flag = False
            alert_msg = ""
            scan_location = "Unknown"

            if len(user_serial) > 3:
                # READ FROM ETHEREUM
                note_data = contract.functions.verifyNote(user_serial).call()
                exists = note_data[3]
                
                if exists:
                    denom = note_data[0]
                    ts = note_data[2]
                    mint_date = datetime.fromtimestamp(ts)

                    result = f"✅ GENUINE! Verified on Ethereum"
                    color = "green"
                    status_log = "Verified"
                    
                    context['block_details'] = {
                        'index': 'ETH-BLOCK',
                        'denomination': denom,
                        'hash': 'Verified on Mainnet',
                        'timestamp': mint_date
                    }
                else:
                    result = f"❌ COUNTERFEIT! Serial '{user_serial}' not found on Chain."
                    color = "red"
                    status_log = "Counterfeit Attempt"
                    suspicious_flag = True 
                    alert_msg = "⚠️ ALERT: Counterfeit Note Detected"

                if request.user.is_authenticated:
                    user_ip = get_client_ip(request)
                    scan_location = f"IP: {user_ip} (IN)"
                    
                    time_threshold = timezone.now() - timedelta(minutes=10)
                    recent = TrackingLog.objects.filter(serial_number=user_serial, timestamp__gte=time_threshold).count()
                    if recent >= 3: 
                        suspicious_flag = True
                        alert_msg = f"⚠️ ALERT: High Frequency Scanning ({recent}+)"

                    TrackingLog.objects.create(
                        serial_number=user_serial, scanned_by=request.user,
                        status=status_log, is_suspicious=suspicious_flag,
                        alert_message=alert_msg, location=scan_location
                    )
            else:
                result = "❌ Error: OCR Failed."
                color = "orange"

        except Exception as e:
            result = f"Error: {str(e)}"
            color = "orange"

        context.update({
            'result': result, 'color': color, 'image_url': fs.url(filename),
            'extracted_text': user_serial, 'is_suspicious': suspicious_flag,
            'alert_msg': alert_msg, 'scan_location': scan_location
        })

    return render(request, 'user.html', context)

# ==========================================
# 4. PDF RECEIPT
# ==========================================
def download_receipt(request, block_id):
    block = Block.objects.get(id=block_id)
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Receipt_{block.serial_no}.pdf"'
    p = canvas.Canvas(response, pagesize=letter)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(100, 750, "CURRENCY GUARD BLOCKCHAIN")
    p.setFont("Helvetica", 12)
    p.drawString(100, 735, "Official Minting Transaction Receipt")
    p.line(100, 720, 500, 720)
    y = 680
    p.setFont("Helvetica-Bold", 12)
    p.drawString(100, y, "TRANSACTION DETAILS:")
    p.setFont("Helvetica", 12)
    p.drawString(120, y-30, f"• Serial Number:  {block.serial_no}")
    p.drawString(120, y-50, f"• Denomination:   Rs. {block.denomination}")
    p.drawString(120, y-70, f"• Block Index:    #{block.index}")
    p.drawString(120, y-90, f"• Mined On:       {block.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    p.setFont("Helvetica-Bold", 12)
    p.drawString(100, y-130, "CRYPTOGRAPHIC PROOF:")
    p.setFont("Courier", 10)
    p.drawString(100, y-150, f"Current Hash: {block.hash}")
    p.drawString(100, y-170, f"Previous Hash: {block.previous_hash}")
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(100, 100, "This document certifies that the currency note above has been cryptographically")
    p.drawString(100, 85, "secured on the Ethereum Blockchain network.")
    p.showPage()
    p.save()
    return response