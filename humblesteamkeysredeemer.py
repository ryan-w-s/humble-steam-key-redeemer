import requests
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from fuzzywuzzy import fuzz
import steam.webauth as wa
import time
import re
import pickle
from pwinput import pwinput
import os
import json
import sys
import webbrowser
import os
from base64 import b64encode
import atexit
import signal
from http.client import responses

#patch steam webauth for password feedback
wa.getpass = pwinput

if __name__ == "__main__":
    sys.stderr = open('error.log','a')

# Humble endpoints
HUMBLE_LOGIN_PAGE = "https://www.humblebundle.com/login"
HUMBLE_KEYS_PAGE = "https://www.humblebundle.com/home/library"
HUMBLE_SUB_PAGE = "https://www.humblebundle.com/subscription/"

HUMBLE_LOGIN_API = "https://www.humblebundle.com/processlogin"
HUMBLE_REDEEM_API = "https://www.humblebundle.com/humbler/redeemkey"
HUMBLE_ORDERS_API = "https://www.humblebundle.com/api/v1/user/order"
HUMBLE_ORDER_DETAILS_API = "https://www.humblebundle.com/api/v1/order/"
HUMBLE_SUB_API = "https://www.humblebundle.com/api/v1/subscriptions/humble_monthly/subscription_products_with_gamekeys/"

HUMBLE_PAY_EARLY = "https://www.humblebundle.com/subscription/payearly"
HUMBLE_CHOOSE_CONTENT = "https://www.humblebundle.com/humbler/choosecontent"

# Steam endpoints
STEAM_KEYS_PAGE = "https://store.steampowered.com/account/registerkey"
STEAM_USERDATA_API = "https://store.steampowered.com/dynamicstore/userdata/"
STEAM_REDEEM_API = "https://store.steampowered.com/account/ajaxregisterkey/"
STEAM_APP_LIST_API = "https://api.steampowered.com/ISteamApps/GetAppList/v2/"

# May actually be able to do without these, but for now they're in.
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json, text/javascript, */*; q=0.01",
}


def find_dict_keys(node, kv, parent=False):
    if isinstance(node, list):
        for i in node:
            for x in find_dict_keys(i, kv, parent):
               yield x
    elif isinstance(node, dict):
        if kv in node:
            if parent:
                yield node
            else:
                yield node[kv]
        for j in node.values():
            for x in find_dict_keys(j, kv, parent):
                yield x

getHumbleOrders = '''
var done = arguments[arguments.length - 1];
var list = '%optional%';
if (list){
    list = JSON.parse(list);
} else {
    list = [];
}
var getHumbleOrderDetails = async (list) => {
  const HUMBLE_ORDERS_API_URL = 'https://www.humblebundle.com/api/v1/user/order';
  const HUMBLE_ORDER_DETAILS_API = 'https://www.humblebundle.com/api/v1/order/';

  try {
    var orders = []
    if(list.length){
      orders = list.map(item => ({ gamekey: item }));
    } else {
      const response = await fetch(HUMBLE_ORDERS_API_URL);
      orders = await response.json();
    }
    const orderDetailsPromises = orders.map(async (order) => {
      const orderDetailsUrl = `${HUMBLE_ORDER_DETAILS_API}${order['gamekey']}?all_tpkds=true`;
      const orderDetailsResponse = await fetch(orderDetailsUrl);
      const orderDetails = await orderDetailsResponse.json();
      return orderDetails;
    });

    const orderDetailsArray = await Promise.all(orderDetailsPromises);
    return orderDetailsArray;
  } catch (error) {
    console.error('Error:', error);
    return [];
  }
};

getHumbleOrderDetails(list).then(r => {done(r)});
'''

fetch_cmd = '''
var done = arguments[arguments.length - 1];
var formData = new FormData();
const jsonData = JSON.parse(atob('{formData}'));

for (const key in jsonData) {{
    formData.append(key,jsonData[key])
}}

fetch("{url}", {{
  "headers": {{
    "csrf-prevention-token": "{csrf}"
    }},
  "body": formData,
  "method": "POST",
}}).then(r => {{ r.json().then( v=>{{done([r.status,v])}} ) }} );
'''

def perform_post(driver,url,payload):
    json_payload = b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')
    csrf = driver.get_cookie('csrf_cookie')
    csrf = csrf['value'] if csrf is not None else ''
    if csrf is None:
        csrf = ''
    script = fetch_cmd.format(formData=json_payload,url=url,csrf=csrf)

    return driver.execute_async_script(fetch_cmd.format(formData=json_payload,url=url,csrf=csrf))

def process_quit(driver):
    def quit_on_exit(*args):
        driver.quit()

    atexit.register(quit_on_exit)
    signal.signal(signal.SIGTERM,quit_on_exit)
    signal.signal(signal.SIGINT,quit_on_exit)

def get_headless_driver():
    possibleDrivers = [(webdriver.Firefox,webdriver.FirefoxOptions),(webdriver.Chrome,webdriver.ChromeOptions)]
    driver = None

    exceptions = []
    for d,opt in possibleDrivers:
        try:
            options = opt()
            if d == webdriver.Chrome:
                options.add_argument("--headless=new")
            else:
                options.add_argument("-headless")
            driver = d(options=options)
            process_quit(driver) # make sure driver closes when we close
            return driver
        except WebDriverException as e:
            exceptions.append(('chrome:' if d == webdriver.Chrome else 'firefox:',e))
            continue
    cls()
    print("This script needs either Chrome or Firefox to be installed and the respective Web Driver for it to be configured (usually simplest is by placing it in the folder with the script)")
    print("")
    print("https://www.browserstack.com/guide/geckodriver-selenium-python")
    print("")
    print("Potential configuration hints:")
    for browser,exception in exceptions:
        print("")
        print(browser,exception.msg)

    time.sleep(30)
    sys.exit()

MODE_PROMPT = """Welcome to the Humble Exporter!
Which key export mode would you like to use?

[1] Auto-Redeem
[2] Export keys
[3] Humble Choice chooser
"""
def prompt_mode(order_details,humble_session):
    mode = None
    while mode not in ["1","2","3"]:
        print(MODE_PROMPT)
        mode = input("Choose 1, 2, or 3: ").strip()
        if mode in ["1","2","3"]:
            return mode
        print("Invalid mode")
    return mode


def valid_steam_key(key):
    # Steam keys are in the format of AAAAA-BBBBB-CCCCC
    if not isinstance(key, str):
        return False
    key_parts = key.split("-")
    return (
        len(key) == 17
        and len(key_parts) == 3
        and all(len(part) == 5 for part in key_parts)
    )


def normalize_title(title):
    # Stricter normalization for exact comparisons: case-insensitive,
    # remove trademark symbols and punctuation, collapse whitespace.
    if not isinstance(title, str):
        return ""
    normalized = title.casefold()
    normalized = normalized.replace("\u2122", "").replace("\u00ae", "").replace("\u00a9", "")
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def get_item_uid(tpk):
    # Stable per-item identifier to avoid order-level (gamekey-only) collisions
    gamekey = str(tpk.get("gamekey", "")).strip()
    keyindex = str(tpk.get("keyindex", "")).strip()
    machine_name = str(tpk.get("machine_name", "")).strip()
    return f"{gamekey}::{keyindex}::{machine_name}"


def try_recover_cookies(cookie_file, session):
    try:
        cookies = pickle.load(open(cookie_file,"rb"))
        if type(session) is requests.Session:
            # handle Steam session
            session.cookies.update(cookies)
        else:
            # handle WebDriver
            for cookie in cookies:
                session.add_cookie(cookie)
        return True
    except Exception as e:
        return False


def export_cookies(cookie_file, session):
    try:
        cookies = None
        if type(session) is requests.Session:
            # handle Steam session
            cookies = session.cookies
        else:
            # handle WebDriver
            cookies = session.get_cookies()
        pickle.dump(cookies, open(cookie_file,"wb"))
        return True
    except:
        return False

is_logged_in = '''
var done = arguments[arguments.length-1];

fetch("https://www.humblebundle.com/home/library").then(r => {done(!r.redirected)})
'''

def verify_logins_session(session):
    # Returns [humble_status, steam_status]
    if type(session) is requests.Session:
        loggedin = session.get(STEAM_KEYS_PAGE, allow_redirects=False).status_code not in (301,302)
        return [False,loggedin]
    else:
        return [session.execute_async_script(is_logged_in),False]

def do_login(driver,payload):
        auth,login_json = perform_post(driver,HUMBLE_LOGIN_API,payload)
        if auth not in (200,401):
            print(f"humblebundle.com has responded with an error (HTTP status code {auth}: {responses[auth]}).")
            time.sleep(30)
            sys.exit()
        return auth,login_json

def humble_login(driver):
    cls()
    driver.get(HUMBLE_LOGIN_PAGE)
    # Attempt to use saved session
    if try_recover_cookies(".humblecookies", driver) and verify_logins_session(driver)[0]:
        return True

    # Saved session didn't work
    authorized = False
    while not authorized:
        username = input("Humble Email: ")
        password = pwinput()


        payload = {
            "access_token": "",
            "access_token_provider_id": "",
            "goto": "/",
            "qs": "",
            "username": username,
            "password": password,
        }

        auth,login_json = do_login(driver,payload)

        if "errors" in login_json and "username" in login_json["errors"]:
            # Unknown email OR mismatched password
            print(login_json["errors"]["username"][0])
            continue

        while "humble_guard_required" in login_json or "two_factor_required" in login_json:
            # There may be differences for Humble's SMS 2FA, haven't tested.
            if "humble_guard_required" in login_json:
                humble_guard_code = input("Please enter the Humble security code: ")
                payload["guard"] = humble_guard_code.upper()
                # Humble security codes are case-sensitive via API, but luckily it's all uppercase!
                auth,login_json = do_login(driver,payload)

                if (
                    "user_terms_opt_in_data" in login_json
                    and login_json["user_terms_opt_in_data"]["needs_to_opt_in"]
                ):
                    # Nope, not messing with this.
                    print(
                        "There's been an update to the TOS, please sign in to Humble on your browser."
                    )
                    sys.exit()
            elif (
                "two_factor_required" in login_json and
                "errors" in login_json
                and "authy-input" in login_json["errors"]
            ):
                code = input("Please enter 2FA code: ")
                payload["code"] = code
                auth,login_json = do_login(driver,payload)
            elif "errors" in login_json:
                print("Unexpected login error detected.")
                print(login_json["errors"])
                raise Exception(login_json)
                sys.exit()
            
            if auth == 200:
                break

        export_cookies(".humblecookies", driver)
        return True


def steam_login():
    # Sign into Steam web

    # Attempt to use saved session
    r = requests.Session()
    if try_recover_cookies(".steamcookies", r) and verify_logins_session(r)[1]:
        return r

    # Saved state doesn't work, prompt user to sign in.
    s_username = input("Steam Username: ")
    user = wa.WebAuth(s_username)
    session = user.cli_login()
    export_cookies(".steamcookies", session)
    return session


def redeem_humble_key(sess, tpk):
    # Keys need to be 'redeemed' on Humble first before the Humble API gives the user a Steam key.
    # This triggers that for a given Humble key entry
    payload = {"keytype": tpk["machine_name"], "key": tpk["gamekey"], "keyindex": tpk["keyindex"]}
    status,respjson = perform_post(sess, HUMBLE_REDEEM_API, payload)
    
    if status != 200 or "error_msg" in respjson or not respjson["success"]:
        print("Error redeeming key on Humble for " + tpk["human_name"])
        if("error_msg" in respjson):
            print(respjson["error_msg"])
        return ""
    try:
        return respjson["key"]
    except:
        return respjson


def get_month_data(humble_session,month):
    # No real API for this, seems to just be served on the webpage.
    if type(humble_session) is not requests.Session:
        raise Exception("get_month_data needs a configured requests session")
    r = humble_session.get(HUMBLE_SUB_PAGE + month["product"]["choice_url"])

    data_indicator = f'<script id="webpack-monthly-product-data" type="application/json">'
    jsondata = r.text.split(data_indicator)[1].split("</script>")[0].strip()
    jsondata = json.loads(jsondata)
    return jsondata["contentChoiceOptions"]


def get_choices(humble_session,order_details):
    months = [
        month for month in order_details 
        if "choice_url" in month["product"] 
    ]

    # Oldest to Newest order
    months = sorted(months,key=lambda m: m["created"])
    request_session = requests.Session()
    for cookie in humble_session.get_cookies():
        # convert cookies to requests
        request_session.cookies.set(cookie['name'],cookie['value'],domain=cookie['domain'].replace('www.',''),path=cookie['path'])

    choices = []
    for month in months:
        if month["choices_remaining"] > 0 or month["product"].get("is_subs_v3_product",False): # subs v3 products don't advertise choices, need to get them exhaustively
            chosen_games = set(find_dict_keys(month["tpkd_dict"],"machine_name"))

            month["choice_data"] = get_month_data(request_session,month)
            if not month["choice_data"].get('canRedeemGames',True):
                month["available_choices"] = []
                continue

            v3 = not month["choice_data"].get("usesChoices",True)
            
            # Needed for choosing
            if v3:
                identifier = "initial"
                choice_options = month["choice_data"]["contentChoiceData"]["game_data"]
            else:
                identifier = "initial" if "initial" in month["choice_data"]["contentChoiceData"] else "initial-classic"
            
                if identifier not in month["choice_data"]["contentChoiceData"]:
                    for key in month["choice_data"]["contentChoiceData"].keys():
                        if "content_choices" in month["choice_data"]["contentChoiceData"][key]:
                            identifier = key

                choice_options = month["choice_data"]["contentChoiceData"][identifier]["content_choices"]

            # Exclude games that have already been chosen:
            month["available_choices"] = [
                    game[1]
                    for game in choice_options.items()
                    if set(find_dict_keys(game[1],"machine_name")).isdisjoint(chosen_games)
            ]
            
            month["parent_identifier"] = identifier
            if len(month["available_choices"]):
                yield month


def _redeem_steam(session, key, quiet=False):
    # Based on https://gist.github.com/snipplets/2156576c2754f8a4c9b43ccb674d5a5d
    if key == "":
        return 0
    session_id = session.cookies.get_dict()["sessionid"]
    r = session.post(STEAM_REDEEM_API, data={"product_key": key, "sessionid": session_id})
    blob = r.json()

    if blob["success"] == 1:
        for item in blob["purchase_receipt_info"]["line_items"]:
            print("Redeemed " + item["line_item_description"])
        return 0
    else:
        error_code = blob.get("purchase_result_details")
        if error_code == None:
            # Sometimes purchase_result_details isn't there for some reason, try alt method
            error_code = blob.get("purchase_receipt_info")
            if error_code != None:
                error_code = error_code.get("result_detail")
        error_code = error_code or 53

        if error_code == 14:
            error_message = (
                "The product code you've entered is not valid. Please double check to see if you've "
                "mistyped your key. I, L, and 1 can look alike, as can V and Y, and 0 and O. "
            )
        elif error_code == 15:
            error_message = (
                "The product code you've entered has already been activated by a different Steam account. "
                "This code cannot be used again. Please contact the retailer or online seller where the "
                "code was purchased for assistance. "
            )
        elif error_code == 53:
            error_message = (
                "There have been too many recent activation attempts from this account or Internet "
                "address. Please wait and try your product code again later. "
            )
        elif error_code == 13:
            error_message = (
                "Sorry, but this product is not available for purchase in this country. Your product key "
                "has not been redeemed. "
            )
        elif error_code == 9:
            error_message = (
                "This Steam account already owns the product(s) contained in this offer. To access them, "
                "visit your library in the Steam client. "
            )
        elif error_code == 24:
            error_message = (
                "The product code you've entered requires ownership of another product before "
                "activation.\n\nIf you are trying to activate an expansion pack or downloadable content, "
                "please first activate the original game, then activate this additional content. "
            )
        elif error_code == 36:
            error_message = (
                "The product code you have entered requires that you first play this game on the "
                "PlayStation®3 system before it can be registered.\n\nPlease:\n\n- Start this game on "
                "your PlayStation®3 system\n\n- Link your Steam account to your PlayStation®3 Network "
                "account\n\n- Connect to Steam while playing this game on the PlayStation®3 system\n\n- "
                "Register this product code through Steam. "
            )
        elif error_code == 50:
            error_message = (
                "The code you have entered is from a Steam Gift Card or Steam Wallet Code. Browse here: "
                "https://store.steampowered.com/account/redeemwalletcode to redeem it. "
            )
        else:
            error_message = (
                "An unexpected error has occurred.  Your product code has not been redeemed.  Please wait "
                "30 minutes and try redeeming the code again.  If the problem persists, please contact <a "
                'href="https://help.steampowered.com/en/wizard/HelpWithCDKey">Steam Support</a> for '
                "further assistance. "
            )
        if error_code != 53 or not quiet:
            print(error_message)
        return error_code


files = {}


def write_key(code, key):
    global files

    # Aggregated legacy files (back-compat)
    filename = "redeemed.csv"
    if code == 15 or code == 9:
        filename = "already_owned.csv"
    elif code != 0:
        filename = "errored.csv"

    if filename not in files:
        files[filename] = open(filename, "a", encoding="utf-8-sig")

    human_name_value = str(key.get("human_name", "")).replace(",", ".")
    gamekey = str(key.get('gamekey', ""))
    redeemed_key_val = str(key.get("redeemed_key_val", ""))
    output = f"{gamekey},{human_name_value},{redeemed_key_val}\n"
    files[filename].write(output)
    files[filename].flush()

    # Reason-based files (compact, human-friendly)
    def write_reason_row(filename_reason, key_reason, reason):
        if not filename_reason:
            return
        if filename_reason not in files:
            files[filename_reason] = open(filename_reason, "a", encoding="utf-8-sig")
        human_name_value_local = str(key_reason.get("human_name", "")).replace(",", ".")
        gamekey_local = str(key_reason.get('gamekey', ""))
        redeemed_key_val_local = str(key_reason.get("redeemed_key_val", ""))
        steam_app_id_local = str(key_reason.get("steam_app_id", ""))
        uid_local = get_item_uid(key_reason)
        row_local = f"{gamekey_local},{human_name_value_local},{redeemed_key_val_local},{steam_app_id_local},{uid_local},{reason}\n"
        files[filename_reason].write(row_local)
        files[filename_reason].flush()

    reason_file = None
    if code == 0:
        reason_file = None  # success is fully captured by redeemed.csv
    elif code in (9, 15):
        reason_file = "owned_steam.csv"
    elif code in (14, 13, 50):
        reason_file = "errors_permanent.csv"
    elif code in (24, 36):
        reason_file = "errors_blocked.csv"
    elif code != 53:  # exclude rate limit; we retry until it changes
        reason_file = "errors_unknown.csv"
    # If code == 53 we don't log here (we spin until non-53)
    if reason_file:
        write_reason_row(reason_file, key, str(code))


def prompt_skipped(skipped_games):
    user_filtered = []
    with open("skipped.txt", "w", encoding="utf-8-sig") as file:
        for skipped_game in skipped_games.keys():
            file.write(skipped_game + "\n")

    print(
        f"Inside skipped.txt is a list of {len(skipped_games)} games that we think you already own, but aren't "
        f"completely sure "
    )
    try:
        input(
            "Feel free to REMOVE from that list any games that you would like to try anyways, and when done press "
            "Enter to confirm. "
        )
    except SyntaxError:
        pass
    if os.path.exists("skipped.txt"):
        with open("skipped.txt", "r", encoding="utf-8-sig") as file:
            user_filtered = [line.strip() for line in file]
        os.remove("skipped.txt")
    # Choose only the games that appear to be missing from user's skipped.txt file
    user_requested = [
        skip_game
        for skip_name, skip_game in skipped_games.items()
        if skip_name not in user_filtered
    ]
    return user_requested


def prompt_yes_no(question):
    ans = None
    answers = ["y","n"]
    while ans not in answers:
        prompt = f"{question} [{'/'.join(answers)}] "

        ans = input(prompt).strip().lower()
        if ans not in answers:
            print(f"{ans} is not a valid answer")
            continue
        else:
            return True if ans == "y" else False

def get_owned_apps(steam_session):
    owned_content = steam_session.get(STEAM_USERDATA_API).json()
    owned_app_ids = owned_content["rgOwnedPackages"] + owned_content["rgOwnedApps"]
    owned_app_details = {
        app["appid"]: app["name"]
        for app in steam_session.get(STEAM_APP_LIST_API).json()["applist"]["apps"]
        if app["appid"] in owned_app_ids
    }
    return owned_app_details

def match_ownership(owned_app_details, game, filter_live):
    # Strict matching: only auto-match when normalized titles are exactly equal.
    target_name_norm = normalize_title(str(game.get("human_name", "")))

    exact_matches = []
    for appid, appname in owned_app_details.items():
        if normalize_title(appname) == target_name_norm:
            exact_matches.append((100, appid))

    if exact_matches:
        # If multiple, choose the one with highest score (all 100) and stable order
        best_match = max(exact_matches, key=lambda item: item[0])
        return best_match

    # No exact normalized match found. In interactive mode, allow very high-similarity review only.
    if filter_live:
        matches = [
            (fuzz.token_sort_ratio(appname, str(game.get("human_name", ""))), appid)
            for appid, appname in owned_app_details.items()
        ]
        refined_matches = [(score, appid) for score, appid in matches if score >= 90]

        if len(refined_matches) > 0:
            cls()
            best_match = max(refined_matches, key=lambda item: item[0])
            if best_match[0] == 100:
                return best_match
            print("steam games you own")
            for match in refined_matches:
                print(f"     {owned_app_details[match[1]]}: {match[0]}")
            if prompt_yes_no(f"Is \"{game['human_name']}\" in the above list?"):
                return refined_matches[0]
        return (0, None)

    # Non-interactive: do not accept fuzzy matches.
    return (0, None)

def prompt_filter_live():
    mode = None
    while mode not in ["y","n"]:
        mode = input("You can either see a list of games we think you already own later in a file, or filter them now. Would you like to see them now? [y/n] ").strip()
        if mode in ["y","n"]:
            return mode
        else:
            print("Enter y or n")
    return mode

def redeem_steam_keys(humble_session, humble_keys):
    session = steam_login()

    print("Successfully signed in on Steam.")
    print("Getting your owned content to avoid attempting to register keys already owned...")

    # Query owned App IDs according to Steam
    owned_app_details = get_owned_apps(session)

    # --- BEGIN PERFORMANCE OPTIMIZATION 1 ---
    # Convert owned app IDs to a set of strings for faster lookups
    owned_app_ids_str_set = set(map(str, owned_app_details.keys()))
    # --- END PERFORMANCE OPTIMIZATION 1 ---

    # Filter out keys for games already directly owned by steam_app_id
    # Keep keys if steam_app_id is missing OR if it's not in the owned_app_details
    noted_keys = []
    # Historical owned-by-appid across previous runs (from logs)
    historical_owned_appids = set()
    for history_file in ("owned_steam.csv", "owned_appid.csv"):
        try:
            with open(history_file, "r", encoding="utf-8-sig") as f_hist:
                for line in f_hist:
                    parts = line.strip().split(',')
                    if len(parts) >= 4 and parts[3] and parts[3].strip().isdigit():
                        historical_owned_appids.add(parts[3].strip())
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"WARNING: Error reading {history_file} for appid cross-referencing: {e}")
    if historical_owned_appids:
        print(f"INFO: Loaded {len(historical_owned_appids)} historical Steam appids from logs for cross-referencing.")

    for key in humble_keys:
        steam_app_id_value = key.get("steam_app_id")
        if (
            steam_app_id_value is not None and (
                str(steam_app_id_value) in owned_app_ids_str_set or
                str(steam_app_id_value) in historical_owned_appids
            )
        ):
            # Log pre-check ownership by appid
            temp_key = dict(key)
            write_key(9, temp_key)  # still writes to legacy already_owned.csv for back-compat
            # Reason-based file for pre-check
            if "owned_appid.csv" not in files:
                files["owned_appid.csv"] = open("owned_appid.csv", "a", encoding="utf-8-sig")
            human_name_value = str(key.get("human_name", "")).replace(",", ".")
            gamekey = str(key.get('gamekey', ""))
            redeemed_key_val = str(key.get("redeemed_key_val", ""))
            steam_app_id_str = str(steam_app_id_value)
            uid = get_item_uid(key)
            files["owned_appid.csv"].write(f"{gamekey},{human_name_value},{redeemed_key_val},{steam_app_id_str},{uid},owned_by_appid\n")
            files["owned_appid.csv"].flush()
            continue
        noted_keys.append(key)
    
    skipped_games = {}
    unownedgames = []

    filter_live = prompt_filter_live() == "y"

    # Load historical data for cross-run dedupe
    confirmed_owned_steam_keys_local = set()
    confirmed_item_uids_local = set()
    try:
        with open("already_owned.csv", "r", encoding="utf-8-sig") as f_ao:
            # write_key doesn't add a header, so no need to skip it here unless manually added.
            for line in f_ao:
                parts = line.strip().split(',')
                if not parts: continue
                # Revealed Steam key string is expected in parts[2]
                if len(parts) >= 3 and parts[2].strip(): 
                    confirmed_owned_steam_keys_local.add(parts[2].strip())
        if confirmed_owned_steam_keys_local:
            print(f"INFO: Loaded {len(confirmed_owned_steam_keys_local)} revealed Steam keys from already_owned.csv for cross-referencing.")
    except FileNotFoundError:
        print("INFO: already_owned.csv not found. Cannot pre-skip keys based on it in this session.")
    except Exception as e:
        print(f"WARNING: Error reading already_owned.csv for cross-referencing: {e}")

    # Also consult owned_steam.csv for definitive owned results with stable item UIDs
    try:
        with open("owned_steam.csv", "r", encoding="utf-8-sig") as f_os:
            for line in f_os:
                parts = line.strip().split(',')
                if not parts:
                    continue
                # Add revealed Steam keys, if present
                if len(parts) >= 3 and parts[2].strip():
                    confirmed_owned_steam_keys_local.add(parts[2].strip())
                # Add per-item UIDs for unrevealed/rehydrated comparisons
                if len(parts) >= 5 and parts[4].strip():
                    confirmed_item_uids_local.add(parts[4].strip())
        if confirmed_item_uids_local:
            print(f"INFO: Loaded {len(confirmed_item_uids_local)} item UIDs from owned_steam.csv for cross-referencing.")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"WARNING: Error reading owned_steam.csv for cross-referencing: {e}")

    # Also consult owned_appid.csv for owned-by-appid determinations
    try:
        with open("owned_appid.csv", "r", encoding="utf-8-sig") as f_oa:
            for line in f_oa:
                parts = line.strip().split(',')
                if len(parts) >= 5 and parts[4].strip():
                    confirmed_item_uids_local.add(parts[4].strip())
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"WARNING: Error reading owned_appid.csv for cross-referencing: {e}")

    for game in noted_keys:
        game_humble_key = game.get("gamekey")
        game_steam_key_val = game.get("redeemed_key_val")
        human_name_for_log = game.get("human_name", "Unknown Game")
        current_item_uid = get_item_uid(game)
        
        is_confirmed_owned_by_csv = False
        reason_for_skip = ""

        # Only skip by exact revealed key or per-item uid, not by order-level gamekey
        if game_steam_key_val and game_steam_key_val in confirmed_owned_steam_keys_local:
            is_confirmed_owned_by_csv = True
            reason_for_skip = f"Revealed Steam key '{game_steam_key_val}' found in already_owned.csv."
        elif current_item_uid and current_item_uid in confirmed_item_uids_local:
            is_confirmed_owned_by_csv = True
            reason_for_skip = f"Item UID '{current_item_uid}' found in granular logs."

        if is_confirmed_owned_by_csv:
            print(f"Skipping fuzzy match for '{human_name_for_log}': {reason_for_skip} Will not be re-prompted via skipped.txt.")
            # Ensure this key's status as 'already owned' is logged correctly in the CSV for this run if it wasn't perfectly captured before.
            # This helps maintain consistency in already_owned.csv.
            write_key(9, game) 
            continue 

        best_match = match_ownership(owned_app_details,game,filter_live)
        # Ensure owned_app_details keys are compared as strings if best_match[1] is int
        if best_match[1] is not None and str(best_match[1]) in owned_app_ids_str_set:
            skipped_games[game["human_name"].strip()] = game
        else:
            unownedgames.append(game)

    print(
        "Filtered out game keys that you already own on Steam (initial check and CSV); {} keys unowned and proceeding to potential fuzzy match review.".format(
            len(unownedgames)
        )
    )

    if len(skipped_games):
        # Skipped games uncertain to be owned by user. Let user choose
        user_approved_from_skipped = prompt_skipped(skipped_games)
        unownedgames.extend(user_approved_from_skipped) # Add user approved games to the list
        # Write the not-approved fuzzy skips to owned_fuzzy.csv
        fuzzy_skipped = [g for name,g in skipped_games.items() if g not in user_approved_from_skipped]
        if len(fuzzy_skipped):
            if "owned_fuzzy.csv" not in files:
                files["owned_fuzzy.csv"] = open("owned_fuzzy.csv", "a", encoding="utf-8-sig")
            for g in fuzzy_skipped:
                human_name_value = str(g.get("human_name", "")).replace(",", ".")
                gamekey = str(g.get('gamekey', ""))
                redeemed_key_val = str(g.get("redeemed_key_val", ""))
                steam_app_id_str = str(g.get("steam_app_id", ""))
                uid = get_item_uid(g)
                files["owned_fuzzy.csv"].write(f"{gamekey},{human_name_value},{redeemed_key_val},{steam_app_id_str},{uid},fuzzy_skip\n")
            files["owned_fuzzy.csv"].flush()
        # Preserve original order from humble_keys
        original_indices = {key.get("gamekey"): i for i, key in enumerate(humble_keys)}
        # Deduplicate while preserving order (important if a game was in unownedgames AND approved from skipped)
        # A bit more involved to preserve order after deduplication from multiple sources
        temp_unowned_dict = {original_indices.get(g.get("gamekey"), float('inf')): g for g in unownedgames}
        sorted_keys_for_dedup = sorted(temp_unowned_dict.keys())
        unownedgames = [temp_unowned_dict[k] for k in sorted_keys_for_dedup]
        print(f"{len(unownedgames)} keys will be attempted after review of potential duplicates.")
    
    if not unownedgames:
        print("No keys to attempt redeeming in this run.")
    else:
        print(f"Attempting to redeem {len(unownedgames)} key(s) on Steam...")
        
    redeemed_during_run = set() 

    for key in unownedgames:
        print(key["human_name"])
        
        # Per-run duplicate guard based on per-item UID and appid
        current_key_app_id_str = f"appid_{key.get('steam_app_id')}" if key.get('steam_app_id') is not None else None
        current_item_uid = get_item_uid(key)
        
        if (current_item_uid and current_item_uid in redeemed_during_run) or \
           (current_key_app_id_str is not None and current_key_app_id_str in redeemed_during_run):
            write_key(9,key) # Log as already owned if detected as duplicate within this run
            continue
        else:
            if current_key_app_id_str is not None:
                redeemed_during_run.add(current_key_app_id_str)
            if current_item_uid:
                redeemed_during_run.add(current_item_uid)

        if "redeemed_key_val" not in key or not key["redeemed_key_val"]:
            redeemed_key_val_from_humble = redeem_humble_key(humble_session, key)
            key["redeemed_key_val"] = redeemed_key_val_from_humble

        if not valid_steam_key(key["redeemed_key_val"]):
            print(f"Invalid or missing Steam key for '{key['human_name']}'. Value: '{key['redeemed_key_val']}'. Skipping Steam redemption.")
            write_key(1, key) 
            continue

        code = _redeem_steam(session, key["redeemed_key_val"])
        animation = "|/-\\"
        seconds = 0
        while code == 53:
            """NOTE
            Steam seems to limit to about 50 keys/hr -- even if all 50 keys are legitimate *sigh*
            Even worse: 10 *failed* keys/hr
            Duplication counts towards Steam's _failure rate limit_,
            hence why we've worked so hard above to figure out what we already own
            """
            current_animation = animation[seconds % len(animation)]
            print(
                f"Waiting for rate limit to go away (takes an hour after first key insert) {current_animation}",
                end="\r",
            )
            time.sleep(1)
            seconds = seconds + 1
            if seconds % 60 == 0:
                # Try again every 60 seconds
                code = _redeem_steam(session, key["redeemed_key_val"], quiet=True)

        write_key(code, key)


def export_mode(humble_session,order_details):
    cls()

    export_key_headers = ['human_name','redeemed_key_val','is_gift','key_type_human_name','is_expired','steam_ownership']

    steam_session = None
    reveal_unrevealed = False
    confirm_reveal = False

    owned_app_details = None

    keys = []
    
    print("Please configure your export:")
    export_steam_only = prompt_yes_no("Export only Steam keys?")
    export_revealed = prompt_yes_no("Export revealed keys?")
    export_unrevealed = prompt_yes_no("Export unrevealed keys?")
    if(not export_revealed and not export_unrevealed):
        print("That leaves 0 keys...")
        sys.exit()
    if(export_unrevealed):
        reveal_unrevealed = prompt_yes_no("Reveal all unrevealed keys? (This will remove your ability to claim gift links on these)")
        if(reveal_unrevealed):
            extra = "Steam " if export_steam_only else ""
            confirm_reveal = prompt_yes_no(f"Please CONFIRM that you would like ALL {extra}keys on Humble to be revealed, this can't be undone.")
    steam_config = prompt_yes_no("Would you like to sign into Steam to detect ownership on the export data?")
    
    if(steam_config):
        steam_session = steam_login()
        if(verify_logins_session(steam_session)[1]):
            owned_app_details = get_owned_apps(steam_session)
    
    desired_keys = "steam_app_id" if export_steam_only else "key_type_human_name"
    keylist = list(find_dict_keys(order_details,desired_keys,True))

    for idx,tpk in enumerate(keylist):
        revealed = "redeemed_key_val" in tpk
        export = (export_revealed and revealed) or (export_unrevealed and not revealed)

        if(export):
            if(export_unrevealed and confirm_reveal):
                # Redeem key if user requests all keys to be revealed
                tpk["redeemed_key_val"] = redeem_humble_key(humble_session,tpk)
            
            if(owned_app_details != None and "steam_app_id" in tpk):
                # User requested Steam Ownership info
                owned = tpk["steam_app_id"] in owned_app_details.keys()
                if(not owned):
                    # Do a search to see if user owns it
                    best_match = match_ownership(owned_app_details,tpk,False)
                    owned = best_match[1] is not None and best_match[1] in owned_app_details.keys()
                tpk["steam_ownership"] = owned
            
            keys.append(tpk)
    
    ts = time.strftime("%Y%m%d-%H%M%S")
    filename = f"humble_export_{ts}.csv"
    with open(filename, 'w', encoding="utf-8-sig") as f:
        f.write(','.join(export_key_headers)+"\n")
        for key in keys:
            row = []
            for col in export_key_headers:
                if col in key:
                    row.append("\"" + str(key[col]) + "\"")
                else:
                    row.append("")
            f.write(','.join(row)+"\n")
    
    print(f"Exported to {filename}")


def choose_games(humble_session,choice_month_name,identifier,chosen):
    for choice in chosen:
        display_name = choice["display_item_machine_name"]
        if "tpkds" not in choice:
            webbrowser.open(f"{HUMBLE_SUB_PAGE}{choice_month_name}/{display_name}")
        else:
            payload = {
                "gamekey":choice["tpkds"][0]["gamekey"],
                "parent_identifier":identifier,
                "chosen_identifiers[]":display_name,
                "is_multikey_and_from_choice_modal":"false"
            }
            status,res = perform_post(driver,HUMBLE_CHOOSE_CONTENT,payload)
            if not ("success" in res or not res["success"]):
                print("Error choosing " + choice["title"])
                print(res)
            else:
                print("Chose game " + choice["title"])


def humble_chooser_mode(humble_session,order_details):
    try_redeem_keys = []
    months = get_choices(humble_session,order_details)
    count = 0
    first = True
    for month in months:
        redeem_all = None
        if(first):
            redeem_keys = prompt_yes_no("Would you like to auto-redeem these keys after? (Will require Steam login)")
            first = False
        
        ready = False
        while not ready:
            cls()
            if month["choice_data"]["usesChoices"]:
                remaining = month["choices_remaining"]
                print()
                print(month["product"]["human_name"])
                print(f"Choices remaining: {remaining}")
            else:
                remaining = len(month["available_choices"])
            print("Available Games:\n")
            choices = month["available_choices"]
            for idx,choice in enumerate(choices):
                title = choice["title"]
                rating_text = ""
                if("review_text" in choice["user_rating"] and "steam_percent|decimal" in choice["user_rating"]):
                    rating = choice["user_rating"]["review_text"].replace('_',' ')
                    percentage = str(int(choice["user_rating"]["steam_percent|decimal"]*100)) + "%"
                    rating_text = f" - {rating}({percentage})"
                exception = ""
                if "tpkds" not in choice:
                    # These are weird cases that should be handled by Humble.
                    exception = " (Must be redeemed through Humble directly)"
                print(f"{idx+1}. {title}{rating_text}{exception}")
            if(redeem_all == None and remaining >= len(choices)):
                redeem_all = True
            else:
                redeem_all = False
            
            if(redeem_all):
                user_input = [str(i+1) for i in range(0,len(choices))]
            else:
                if(redeem_keys):
                    auto_redeem_note = "(We'll auto-redeem any keys activated via the webpage if you continue after!)"
                else:
                    auto_redeem_note = ""
                print("\nOPTIONS:")
                print("To choose games, list the indexes separated by commas (e.g. '1' or '1,2,3')")
                print(f"Or type just 'link' to go to the webpage for this month {auto_redeem_note}")
                print("Or just press Enter to move on.")

                user_input = [uinput.strip() for uinput in input().split(',') if uinput.strip() != ""]

            if(len(user_input) == 0):
                ready = True
            elif(user_input[0].lower() == 'link'):
                webbrowser.open(HUMBLE_SUB_PAGE + month["product"]["choice_url"])
                if redeem_keys:
                    # May have redeemed keys on the webpage.
                    try_redeem_keys.append(month["gamekey"])
            else:
                invalid_option = lambda option: (
                    not option.isnumeric()
                    or option == "0" 
                    or int(option) > len(choices)
                )
                invalid = [option for option in user_input if invalid_option(option)]

                if(len(invalid) > 0):
                    print("Error interpreting options: " + ','.join(invalid))
                    time.sleep(2)
                else:
                    user_input = set(int(opt) for opt in user_input) # Uniques
                    chosen = [choice for idx,choice in enumerate(choices) if idx+1 in user_input]
                    # This weird enumeration is to keep it in original display order

                    if len(chosen) > remaining:
                        print(f"Too many games chosen, you have only {remaining} choices left")
                        time.sleep(2)
                    else:
                        print("\nGames selected:")
                        for choice in chosen:
                            print(choice["title"])
                        confirmed = True if redeem_all else prompt_yes_no("Please type 'y' to confirm your selection")
                        if confirmed:
                            choice_month_name = month["product"]["choice_url"]
                            identifier = month["parent_identifier"]
                            choose_games(humble_session,choice_month_name,identifier,chosen)
                            if redeem_keys:
                                try_redeem_keys.append(month["gamekey"])
                            ready = True
    if(first):
        print("No Humble Choices need choosing! Look at you all up-to-date!")
    else:
        print("No more unchosen Humble Choices")
        if(redeem_keys and len(try_redeem_keys) > 0):
            print("Redeeming keys now!")
            updated_monthlies = humble_session.execute_async_script(getHumbleOrders.replace('%optional%',json.dumps(try_redeem_keys)))
            chosen_keys = list(find_dict_keys(updated_monthlies,"steam_app_id",True))
            redeem_steam_keys(humble_session,chosen_keys)

def cls():
    os.system('cls' if os.name=='nt' else 'clear')
    print_main_header()

def print_main_header():
    print("-=FailSpy's Humble Bundle Helper!=-")
    print("--------------------------------------")
    
if __name__=="__main__":
    # Create a consistent session for Humble API use
    driver = get_headless_driver()
    humble_login(driver)
    print("Successfully signed in on Humble.")

    print(f"Getting order details, please wait")

    order_details = driver.execute_async_script(getHumbleOrders.replace('%optional%',''))

    desired_mode = prompt_mode(order_details,driver)
    if(desired_mode == "2"):
        export_mode(driver,order_details)
        sys.exit()
    if(desired_mode == "3"):
        humble_chooser_mode(driver,order_details)
        sys.exit()

    # Auto-Redeem mode
    cls()
    unrevealed_keys = []
    revealed_keys = []
    steam_keys = list(find_dict_keys(order_details,"steam_app_id",True))

    # Pre-run filtering: only suppress by terminal outcomes
    # Files used: redeemed.csv, owned_steam.csv, errors_permanent.csv, owned_appid.csv
    original_length = len(steam_keys)
    suppress_keys = set()
    suppress_files = ["redeemed.csv", "owned_steam.csv", "errors_permanent.csv", "owned_appid.csv"]
    for filter_file in suppress_files:
        try:
            with open(filter_file, "r", encoding="utf-8-sig") as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 3 and parts[2].strip():
                        suppress_keys.add(parts[2].strip())
        except FileNotFoundError:
            pass
    # Also suppress by stable per-item UID from owned_steam.csv and owned_appid.csv so we do not prompt again
    suppress_uids = set()
    for uid_source in ("owned_steam.csv", "owned_appid.csv"):
        try:
            with open(uid_source, "r", encoding="utf-8-sig") as f_uid:
                for line in f_uid:
                    parts = line.strip().split(',')
                    if len(parts) >= 5 and parts[4].strip():
                        suppress_uids.add(parts[4].strip())
        except FileNotFoundError:
            pass

    # Also suppress by Steam appid based on history from owned_steam.csv and owned_appid.csv
    suppress_appids = set()
    for appid_source in ("owned_steam.csv", "owned_appid.csv"):
        try:
            with open(appid_source, "r", encoding="utf-8-sig") as f_app:
                for line in f_app:
                    parts = line.strip().split(',')
                    if len(parts) >= 4 and parts[3] and parts[3].strip().isdigit():
                        suppress_appids.add(parts[3].strip())
        except FileNotFoundError:
            pass

    steam_keys = [
        key for key in steam_keys
        if (
            not key.get("redeemed_key_val") or key.get("redeemed_key_val") not in suppress_keys
        ) and get_item_uid(key) not in suppress_uids
        and (
            not key.get("steam_app_id") or str(key.get("steam_app_id")) not in suppress_appids
        )
    ]
    if len(steam_keys) != original_length:
        print("Filtered {} keys from previous runs".format(original_length - len(steam_keys)))

    for key in steam_keys:
        if "redeemed_key_val" in key:
            revealed_keys.append(key)
        else:
            # Has not been revealed via Humble yet
            unrevealed_keys.append(key)

    print(
        f"{len(steam_keys)} Steam keys total -- {len(revealed_keys)} revealed, {len(unrevealed_keys)} unrevealed"
    )

    will_reveal_keys = prompt_yes_no("Would you like to redeem on Humble as-yet un-revealed Steam keys?"
                                " (Revealing keys removes your ability to generate gift links for them)")
    if will_reveal_keys:
        try_already_revealed = prompt_yes_no("Would you like to attempt redeeming already-revealed keys as well?")
        # User has chosen to either redeem all keys or just the 'unrevealed' ones.
        redeem_steam_keys(driver, steam_keys if try_already_revealed else unrevealed_keys)
    else:
        # User has excluded unrevealed keys.
        redeem_steam_keys(driver, revealed_keys)

    # Cleanup
    for f in files:
        files[f].close()
