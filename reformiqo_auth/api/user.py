import frappe
from frappe import auth
import base64
from frappe_doc import bruno

@frappe.whitelist( allow_guest=True )
@bruno("post")
def login(usr, pwd):
    
    try:
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(user=usr, pwd=pwd)
        login_manager.post_login()
    except frappe.exceptions.AuthenticationError:

        frappe.local.response.update(
            {
                "http_status_code": 401,
                "data": {
                    "success": False,
                    "message":"Authentication Error!"
                }
            }
        )
        return
       
    user = frappe.get_doc('User', frappe.session.user)
    

    data = {
        "sid":frappe.session.sid,
        "username":user.username,
        "email":user.email,
    }
    frappe.local.response.pop("message")
    frappe.local.response.pop("home_page")
    frappe.local.response.pop("full_name")
    frappe.local.response.update(
        {
            "http_status_code": 200,
            "data": data
        }
    )




@frappe.whitelist()
def generate_keys():
    user = frappe.session.user
    user_details = frappe.get_doc('User', user)
    api_secret = frappe.generate_hash(length=20)

    api_key = frappe.generate_hash(length=15)
    user_details.api_key = api_key

    user_details.api_secret = api_secret
    user_details.save()
    frappe.db.commit()
    api_key = user_details.api_key

   

    frappe.local.response.update(
        {
            "http_status_code": 200,
            "data": {
                "api_key":api_key,
                "api_secret":api_secret
            }
        }
    )


@frappe.whitelist()
@bruno()
def get_profile():
    try:
        user = frappe.session.user
        profile = frappe.get_doc("User", user)
        data = {
            "first_name":profile.first_name if profile.first_name else "",
            "last_name":profile.last_name if profile.last_name else "",
            "address":profile.location if profile.location else "",
            "phone_number":profile.phone if profile.phone else "",
            "email":profile.email if profile.email else "",
            "is_verified": True if profile.is_verified else False,
        }
        frappe.local.response.update({
            "http_status_code": 200,
            "data": data
        })
    except Exception as e:
        # log the error
        frappe.log_error(frappe.get_traceback())
        frappe.local.response.update({
            "http_status_code": 500,
            "error": str(e)
        })



@frappe.whitelist()
@bruno("put")
def update_profile(
        first_name:str,
        last_name:str,
        address:str,
        phone_number:str,
    ):

    try:
        user = frappe.session.user
        profile = frappe.get_doc("User", user)
        profile.first_name = first_name
        profile.last_name = last_name
        profile.location = address
        profile.phone = phone_number
        profile.save()
        frappe.db.commit()
        data = {
            "first_name":profile.first_name if profile.first_name else "",
            "last_name":profile.last_name if profile.last_name else "",
            "address":profile.location if profile.location else "",
            "phone_number":profile.phone if profile.phone else "",

        }

        frappe.local.response.update({
            "status_code": 200,
            "data": data
        })
    except Exception as e:
        # log the error
        frappe.log_error(frappe.get_traceback(), "Profile update error")
        frappe.local.response.update({
            "status_code": 500,
            "error": str(e)
        })

@frappe.whitelist(allow_guest=True)
@bruno("post")
def signup(
        first_name:str,
        last_name:str,
        address:str,
        phone_number:str,
        email:str,
        password:str,
    ):
    try:
        
        user = frappe.get_doc({
            "doctype":"User",
            "email":email,
            "first_name":first_name,
            "last_name":last_name,
            "location":address,
            "phone":phone_number,
            "username": email,
            "new_password":password,
            "send_welcome_email": 0
        })
        user.insert(ignore_permissions=True)
        # login the user after signup 
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(user=email, pwd=password)
        login_manager.post_login()
        
        frappe.db.commit()
        frappe.local.response.update({
            "status_code": 200,
            "data": {
                "first_name":user.first_name,
                "last_name":user.last_name,
                "address":user.location,
                "phone_number":user.phone,
                "email":user.email,
                "sid":frappe.session.sid

            }

        })
    except Exception as e:
        # log the error
        frappe.log_error(frappe.get_traceback(), "User Signup Error")
        frappe.clear_messages()
        frappe.local.response.update({
            "status_code": 500,
            "error": str(e)
        })
