def checkAuthorization():
    # check if the card number and pin are okay
    return True


def checksum(value):
    return value == "SHA-256"


def checkDuplicate(context):
    for item in context['DB']:
        if item['sid'] == context['PM']['sid'] or item['NonCPG'] == context['PM']['NonCPG']:
            return False
    return True


def checkBalance(context):
    for item in context['DB']:
        if item['CardInf'] == context['PM']['CardInf']:
            return item['Balance'] - context['PM']['Amount'] >= 0
    return False


def storeTransaction(t, session_data, DB):
    # store transaction inside the DB
    pass
