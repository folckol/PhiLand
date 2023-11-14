import random
import ssl
import time
import traceback
import cloudscraper
import requests
import warnings

import ua_generator
import web3
from web3 import Web3

from utils.logger import logger

warnings.filterwarnings("ignore", category=DeprecationWarning)

abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"AllreadyClaimedObject","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"signer","type":"address"},{"internalType":"bytes32","name":"digest","type":"bytes32"},{"components":[{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"},{"internalType":"uint8","name":"v","type":"uint8"}],"internalType":"struct PhiClaim.Coupon","name":"coupon","type":"tuple"}],"name":"ECDSAInvalidSignature","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"}],"name":"NotAdminCall","type":"error"},{"anonymous":false,"inputs":[],"name":"Hello","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint8","name":"version","type":"uint8"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"tokenid","type":"uint256"}],"name":"LogClaimObject","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"verifierAddress","type":"address"}],"name":"SetAdminSigner","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"condition","type":"string"},{"indexed":false,"internalType":"uint256","name":"tokenid","type":"uint256"}],"name":"SetCoupon","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"contractAddress","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"checkClaimedStatus","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"contractAddress","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"string","name":"condition","type":"string"},{"components":[{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"},{"internalType":"uint8","name":"v","type":"uint8"}],"internalType":"struct PhiClaim.Coupon","name":"coupon","type":"tuple"}],"name":"claimQuestObject","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getAdminSigner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"condition","type":"string"}],"name":"getCouponType","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"admin","type":"address"},{"internalType":"address","name":"adminSigner","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"phiClaimedLists","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"verifierAdderss","type":"address"}],"name":"setAdminSigner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"condition","type":"string"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"setCouponType","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]'


class PhiLand:

    def __init__(self, address, private, proxy, logger):
        self.logger = logger
        self.access_token = None
        self.refresh_token = None
        self.password_ = None

        self.ua = self.generate_user_agent


        self.private, self.address = private, address
        self.session = self._make_scraper
        self.proxy = proxy
        self.session.proxies = {"http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
                                "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.session.headers.update({"user-agent": self.ua,
                                     'content-type': 'application/json',
                                     'Dnt':'1'})

    def mint(self, private_key, tokenId, condition, r, s, v, contractAddress=Web3.to_checksum_address('0x3D8C06e65ebf06A9d40F313a35353be06BD46038')):
        web3 = Web3(Web3.HTTPProvider('https://polygon.llamarpc.com'))

        my_address = web3.eth.account.from_key(private_key).address

        contract_address = '0x754e78bc0f7b487d304552810a5254497084970c'
        contract = web3.eth.contract(Web3.to_checksum_address(contract_address), abi=abi)

        transaction = contract.functions.claimQuestObject(
            contractAddress,
            tokenId,
            condition,
            [r, s, v]
        ).build_transaction({
            'chainId': web3.eth.chain_id,
            'from': my_address,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(my_address),
        })

        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)

        return txn_hash.hex()

    def GetQuestInfo(self, condition, value) -> dict:
        # print(condition, value)
        with self.session.get(f'https://object-api.phi.blue/v1/quest_objects?address={self.address}&condition={condition}&value={value}') as response:
            return response.json()['coupon']

    @property
    def AllQuests(self) -> list:

        with self.session.get(f'https://utils-api.phi.blue/v1/philand/condition/progress?address={self.address}') as response:
            return response.json()['result']


    @property
    def Checker(self) -> list:


        with self.session.get(f'https://utils-api.phi.blue/v1/philand/condition/check?address={self.address}') as response:
            # print(response.text)
            return response.json()['result']


    @property
    def generate_user_agent(self) -> str:
        return ua_generator.generate(platform="windows").text

    @property
    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

if __name__ == '__main__':


    privates = []
    proxies = []
    addresses = []
    delayTrans = None
    delayAccs = None

    try:
        with open('config', 'r', encoding='utf-8') as file:
            for i in file:
                if 'delayTrans=' in i.rstrip():
                    delayTrans = (int(i.rstrip().split('delayTrans=')[-1].split('-')[0]),
                                int(i.rstrip().split('delayTrans=')[-1].split('-')[1]))
                elif 'delayAccs=' in i.rstrip():
                    delayAccs = (int(i.rstrip().split('delayAccs=')[-1].split('-')[0]),
                                int(i.rstrip().split('delayAccs=')[-1].split('-')[1]))

    except:
        traceback.print_exc()
        print('Вы неправильно настроили конфигуратор, повторите попытку')
        input()
        exit(0)

    with open('InputData/Privates.txt', 'r') as file:
        for i in file:
            privates.append(i.rstrip())

    with open('InputData/Addresses.txt', 'r') as file:
        for i in file:
            addresses.append(i.rstrip())

    with open('InputData/Proxies.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())



    count = 0
    while count < len(addresses):

        try:
            acc = PhiLand(web3.Web3.to_checksum_address(addresses[count]),
                          privates[count],
                          proxies[count],
                          logger)

            allQuests = acc.AllQuests
            quests = acc.Checker

            for quest in quests:
                for i in allQuests:
                    if i['TokenId'] == quest:
                        Condition = i['Condition']
                        Value = str(i['Value']).replace('.','p')
                        break
                try:
                    info = acc.GetQuestInfo(Condition, Value)

                    hash = acc.mint(acc.private, quest, Condition+Value, info['r'], info['s'], info['v'])

                    logger.success('{} | {} - Сминчен успешно, хэш - {}'.format(acc.address, Condition, hash))

                except NameError:
                    logger.error('{} | {} - Квест уже был сминчен / другая ошибка'.format(acc.address, Condition))

                except Exception as e:
                    # traceback.print_exc()
                    logger.error('{} | {} - Ошибка ({})'.format(acc.address, Condition, str(e)))

                time.sleep(random.randint(delayTrans[0],delayTrans[1]))

            logger.info("{} | Аккаунт готов".format(acc.address))

        except Exception as e:

            logger.error("{} | Неизвестная ошибка ({})".format(addresses[count], str(e)))


        time.sleep(random.randint(delayAccs[0], delayAccs[1]))
        print('')
        count+=1

    input('\nСкрипт завершил работу...')






