import os
import json
import logging
import re
import urllib3
import boto3
from datetime import datetime
from typing import Optional

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

http = urllib3.PoolManager()

base_dir = os.path.dirname(os.path.dirname(__file__))

with open(base_dir + '/env.json') as f:
    env = json.load(f)


class Settings:
    user_id = env.get('USER_ID')
    password = env.get('PASSWORD')
    duns = env.get('DUNS')
    table_name = env.get('TABLE_NAME')
    company_name = env.get('COMPANY_NAME')
    token_filename = os.path.join(base_dir, 'tmp', 'token.json')


class DirectAPI:
    base_url = 'https://direct.dnb.com'

    _auth_token = None
    print('tablename: ', Settings.table_name)
    table = boto3.resource('dynamodb').Table(Settings.table_name)

    def __init__(self, body: dict) -> None:
        self.body = body

    @property
    def headers_with_token(self):
        if not self.auth_token:
            self.get_token()

        return {
            'Method': 'GET',
            'Content-Type': 'application/json',
            'Authorization': self.auth_token
        }

    @property
    def auth_token(self) -> Optional[str]:
        if self._auth_token is None:
            with open(Settings.token_filename) as f:
                token_data = json.load(f)
            if token_data.get('token'):
                if (
                    datetime.now() - datetime.strptime(
                        token_data.get('date'), "%d-%b-%Y (%H:%M:%S.%f)")
                        ).total_seconds()/3600 < 24:
                    self._auth_token = token_data.get('token')
        return self._auth_token

    @auth_token.setter
    def auth_token(self, value: str):
        with open(Settings.token_filename, 'w+') as f:
            date = datetime.now()
            token_data = {
                'token': value,
                'date': date.strftime("%d-%b-%Y (%H:%M:%S.%f)")
            }
            json.dump(token_data, f)
        self._auth_token = value

    def get_token(self) -> dict:
        '''
        Get Token: A code has to be requested every 24 hrs
        '''
        body = self.body
        try:
            LOGGER.info(json.dumps(body))
            http = urllib3.PoolManager()
            encoded_data = json.dumps(body).encode('utf-8')
            url = self.base_url + '/Authentication/V2.0/'
            LOGGER.info('calling url: ' + str(url))
            r = http.request(
                'POST',
                url,
                body=encoded_data,
                headers={
                    'Content-Type': 'application/json',
                    'x-dnb-user': Settings.user_id,
                    'x-dnb-pwd': Settings.password
                }
            )
            LOGGER.info('Completed api call')
            mdata = json.loads(r.data.decode('utf-8'))

            LOGGER.info(mdata)
            LOGGER.info(mdata.get('TransactionResult'))
            LOGGER.info(mdata.get('ResultMessage'))

            authentication_detail = mdata.get('AuthenticationDetail')
            LOGGER.info(authentication_detail)

            token = authentication_detail.get('Token')

        except Exception as e:
            LOGGER.info('error occured' + str(e))
            raise Exception(e)
        self.auth_token = token

    def lambda_handler(self):
        self.findGeneralCompanyInfo()
        self.findCompanyCompetitors()
        self.findGeneralCompanyNews()
        self.findCompanyBackgroudInfo()
        self.searchforcompany()

    def get_request(self, url):
        headers = self.headers_with_token
        headers['url'] = url

        try:
            r = http.request(
                'get',
                url,
                headers=headers
            )
        except Exception as e:
            LOGGER.info('error occured:' + str(e))
            raise Exception(e)

        LOGGER.info('Completed api call')
        LOGGER.info(r)
        try:
            raw_data = json.loads(r.data.decode('utf-8'))
        except Exception as e:
            match = re.findall(
                        r"{.+[:,].+}|\[.+[,:].+\]", r.data.decode('utf-8'))
            raw_data = json.loads(match[0]) if match else None
            print(e)
        LOGGER.info(json.dumps(raw_data))
        print(raw_data)
        return raw_data

    def insert_dynamodb(self, duns: str, data: dict):
        try:
            duns_num = data.get(
                        'OrderProductResponse').get(
                        'OrderProductResponseDetail').get(
                        'InquiryDetail').get('DUNSNumber')
        except Exception as e:
            print(e)
            duns_num = duns
        try:
            company_name = data.get(
                                'OrderProductResponse').get(
                                'OrderProductResponseDetail').get(
                                'Product').get(
                                'Organization').get(
                                'OrganizationName').get(
                                'OrganizationPrimaryName')[0].get(
                                'OrganizationName').get('$')
        except Exception as e:
            print(e)
            company_name = Settings.company_name
        try:
            address = data.get(
                        'OrderProductResponse').get(
                        'OrderProductResponseDetail').get(
                        'Product').get(
                        'Organization').get(
                        'Location').get(
                        'PrimaryAddress')[0]
        except Exception as e:
            print(e)
            address = ''
        try:
            minority_indicator = data.get(
                                    'OrderProductResponse').get(
                                    'OrderProductResponseDetail').get(
                                    'Product').get(
                                    'Organization').get(
                                    'SocioEconomicIdentification').get(
                                    'MinorityOwnedIndicator')
        except Exception as e:
            print(e)
            minority_indicator = ''
        print(data)

        item = {
            'duns': duns_num,
            'company_name': company_name,
            'name': company_name,
            'address': json.dumps(address),
            'minority_indicator': minority_indicator
        }
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            print(str(e))
            return False

    def findGeneralCompanyInfo(self) -> dict:
        """Getting Detailed Company Profile
        """
        duns = '804735132'
        url = self.base_url + '/V5.0/organizations/{}/products/DCP_STD'.format(
            duns
        )
        raw_data = self.get_request(url)
        self.insert_dynamodb(duns, raw_data)

    def findCompanyCompetitors(self):
        """Getting CompanyCompatitors
        """
        duns = '884114609'
        url = self.base_url + \
            '/V3.0/organizations/{}/products/NEWS_MDA'.format(duns)
        raw_data = self.get_request(url)
        self.insert_dynamodb(duns, raw_data)

    def findGeneralCompanyNews(self):
        """Getting GeneralCompany News
        """
        duns = '884114609'
        url = self.base_url + \
            '/V3.0/organizations/{}/products/NEWS_MDA'.format(duns)
        raw_data = self.get_request(url)
        self.insert_dynamodb(duns, raw_data)

    def findCompanyBackgroudInfo(self):
        url = self.base_url + \
                '/V3.2/organizations/{}/products/'.format(Settings.duns) + \
                'BBR?ProductFormatPreferenceCode=15106' + \
                '&IncludeAttachmentIndicator=true'
        raw_data = self.get_request(url)
        self.insert_dynamodb(Settings.duns, raw_data)

    def searchforcompany(self):
        duns = '804735132'
        url = self.base_url + '/V7.0/organizations/{}/products/DVR_ENH'.format(
            duns
        )
        raw_data = self.get_request(url)
        self.insert_dynamodb(duns, raw_data)


def index(event: dict, context):
    body = event.get('TransactionDetail')
    print('index: ', body)
    LOGGER.info(json.dumps(body, indent=3))
    direct = DirectAPI(body)
    direct.lambda_handler()
    return {
        'statusCode': 200,
        'body': json.dumps(event),
        'isBase64Encoded': 'true'
    }
