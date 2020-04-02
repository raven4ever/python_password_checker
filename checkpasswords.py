import hashlib
import sys

import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def generate_sha1_hash(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def lookup_chars_in_response(api_response, lookup_chars):
    hashes = (line.split(':') for line in api_response.text.splitlines())
    for h, count in hashes:
        if h == lookup_chars:
            return count
    return 0


def count_pwned_occurrences(password):
    sha1_password = generate_sha1_hash(password)
    first5_chars, tail_chars = sha1_password[:5], sha1_password[5:]
    api_response = request_api_data(first5_chars)

    return lookup_chars_in_response(api_response, tail_chars)


def main(args):
    for password in args:
        count = count_pwned_occurrences(password)
        if count:
            print(
                f'{password} was found {count} times, you should probably change it!')
        else:
            print(f'{password} was NOT found. Maybe you\'re safe!')


if __name__ == '__main__':
    main(sys.argv[1:])
