# Python Backend Pseudocode
import random
import hashlib
import time
from datetime import datetime, timedelta
import requests
import frappe
from frappe_doc import bruno
import json

import hashlib
import secrets
from datetime import datetime, timedelta
from frappe.utils import getdate, cint

config = frappe.get_site_config()



@frappe.whitelist(allow_guest=True)
@bruno("post")
def generate_signup_otp(email:str):
    """Generate OTP for Reformiqo signup process"""
    try:
        user = frappe.get_doc("User", email)
        recipient_name = user.first_name
        # Check rate limiting

        otp_code = "".join([str(random.randint(0, 9)) for _ in range(5)])

        # Generate salt and hash OTP for storage
        salt = secrets.token_hex(8)
        hashed_token = hashlib.sha256((otp_code + salt).encode()).hexdigest()

        # Create OTP record
        otp_doc = frappe.get_doc(
            {
                "doctype": "OTP",
                "otp_code": otp_code,
                "email": email,
                "hashed_otp": hashed_token,
                "otp_salt": salt,
                "expiry": datetime.now() + timedelta(minutes=10),
                "ip_address": (
                    frappe.local.request_ip
                    if hasattr(frappe.local, "request_ip")
                    else "Unknown"
                ),
            }
        )
        otp_doc.insert(ignore_permissions=True)


        send_otp_via_email(recipient_name, email, otp_code)

        frappe.local.response.update(
            {
                "http_status_code": 200,
                "data": "Verification code sent successfully to your email",
            }
        )

    except Exception as e:
        frappe.log_error(f"OTP Generation Error: {str(e)}", "Reformiqo OTP")
        frappe.local.response.update(
            {"http_status_code": 500, "error": "Failed to generate verification code"}
        )


@frappe.whitelist(allow_guest=True)
@bruno("post")
def verify_signup_otp(otp_code, email:str):
    """Verify OTP for Reformiqo signup"""
    try:
        

        filters = {"status": "Pending", "expiry": (">", datetime.now())}
        user_filers = {"is_verified": 0}

        otps = frappe.get_all(
            "OTP", filters, ["name", "otp_code", "otp_salt"], order_by="creation asc"
        )

        if not otps:
            frappe.local.response.update(
                {
                    "http_status_code": 400,
                    "error": "No active verification code found or code has expired",
                }
            )
            return

        otp = frappe.get_doc("OTP", filters)
        otp = frappe.get_doc("OTP", filters)

        # Check attempts
        if cint(otp.attempts) >= 3:
            frappe.db.set_value("OTP", otp.name, "status", "Expired")
            frappe.db.commit()
            frappe.local.response.update(
                {
                    "http_status_code": 400,
                    "error": "Too many failed attempts. Request a new verification code.",
                }
            )
            return

        # Increment attempt counter
        frappe.db.set_value("OTP", otp.name, "attempts", cint(otp.attempts) + 1)
        frappe.db.commit()

        # Hash the entered OTP with stored salt
        entered_hash = hashlib.sha256((otp_code + otp.otp_salt).encode()).hexdigest()

        # Verify OTP
        if entered_hash == otp.hashed_otp:
            # Mark as used
            frappe.db.set_value("OTP", otp.name, "status", "Verified")
            # set the user as verified
            # email = otp.email
            frappe.db.set_value("User", email, "is_verified", 1)
            frappe.db.commit()

            frappe.local.response.update(
                {"http_status_code": 200, "data": "Verification successful."}
            )

        else:
            remaining = 2 - otp.attempts
            frappe.local.response.update(
                {
                    "http_status_code": 400,
                    "error": f"Invalid verification code. {remaining} attempts remaining.",
                }
            )
            return

    except Exception as e:
        frappe.log_error(f"OTP Verification Error: {str(e)}", "Reformiqo OTP")
        return {"success": False, "message": "Verification failed. Please try again."}





@frappe.whitelist(allow_guest=True)
def send_otp_via_email(recipient_name, recipient_email, otp):
    url = "https://api.zeptomail.com/v1.1/email/template"

    payload = {
        "template_key": config.get("template_key"),
        "from": {"address": "app@erpera.io", "name": "Erpera"},
        "to": [{"email_address": {"address": recipient_email, "name": recipient_name}}],
        "merge_info": {
                    "product name": config.get("product_name"),
                    "product": config.get("product"),
                    "OTP": otp,
                    "valid_time": "10 minutes",
                    "support id": config.get("support_id"),
                    "brand": config.get("brand")
                },
        "reply_to": [{"address": "support@reformiqo.com", "name": "Reformiqo Support"}],
        "client_reference": "OTP_VERIFICATION",
    }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": config.get("zepto_mail_api_key"),
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    return response.json()


@frappe.whitelist()
def send_user_signup_otp(doc, method=None):
    try:
        generate_signup_otp()
    except Exception as e:
        frappe.throw(str(e))


@frappe.whitelist(allow_guest=True)
@bruno("post")
def resend_otp():
    try:
        user = frappe.get_doc("User", frappe.session.user)
        if not user:
            frappe.throw("User not found")
        generate_signup_otp()
    except Exception as e:
        frappe.throw(str(e))

