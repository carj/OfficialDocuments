import configparser
import csv
import os
import base64
import uuid
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
from boto3.s3.transfer import TransferConfig
from pyPreservica import *
from pathlib import Path
import xml.etree.ElementTree

from requests.auth import HTTPBasicAuth

BAR_CODE = 'Bar code'
SHELF = 'shelf location'
TITLE = 'Title'
TRANS_TITLE = 'Translated Title'
DATE_START = 'Date Range start'
DATE_END = 'Date range end'
SYMBOL = 'Document Symbol (range) (if available)'
SECTION = 'Section'
BODY = 'Body'
AUTHOR = 'Author (named individual(s) only)'
SALES = 'Sales Publication (entire volume only)'
PUB_NO = 'Sales Pub No.'
LANGUAGE = 'language'
LOT = 'LOT'

transfer_config = boto3.s3.transfer.TransferConfig()


class ProgressPercentage:

    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write("\r%s  %s / %s  (%.2f%%)" % (self._filename, self._seen_so_far, self._size, percentage))
            sys.stdout.flush()


class CSVFixityCallBack:

    def __init__(self, csv_folder):
        self.csv_folder = csv_folder

    def __call__(self, filename, full_path):
        path = Path(full_path)
        csv_name = str(path.with_suffix('.csv'))
        csv_name = csv_name.replace("JP2", "CSV")
        fixity_value = ""
        with open(csv_name, mode='r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=',')
            for row in csv_reader:
                fixity_value = row['file_checksum_sha256']

        return "SHA256", fixity_value.lower()

def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def decrypt(key, cypher_text):
    base64_decoded = base64.b64decode(cypher_text)
    aes = cryptography.hazmat.primitives.ciphers.algorithms.AES(key.encode("UTF-8"))
    cipher = Cipher(algorithm=aes, mode=modes.ECB())
    decryptor = cipher.decryptor()
    output_bytes = decryptor.update(base64_decoded) + decryptor.finalize()
    return _unpad(output_bytes.decode("utf-8"))

def session_key(server, bucket_name, username, password, aeskey):
    request = requests.get(f"https://{server}/api/admin/locations/upload?refresh={bucket_name}",
                           auth=HTTPBasicAuth(username, password))
    if request.status_code == requests.codes.ok:
        xml_response = str(request.content.decode('utf-8'))
        entity_response = xml.etree.ElementTree.fromstring(xml_response)
        a = entity_response.find('.//a')
        b = entity_response.find('.//b')
        c = entity_response.find('.//c')
        aws_type = entity_response.find('.//type')
        endpoint = entity_response.find('.//endpoint')

        access_key = decrypt(aeskey, a.text)
        secret_key = decrypt(aeskey, b.text)
        session_token = decrypt(aeskey, c.text)
        source_type = decrypt(aeskey, aws_type.text)
        endpoint = decrypt(aeskey, endpoint.text)

        return access_key, secret_key, session_token, source_type, endpoint


def get_metadata_doc(metadata_map):
    xml_object = xml.etree.ElementTree.Element('OfficialDocuments', {"xmlns": "https://archive.unog.ch/od"})
    xml.etree.ElementTree.SubElement(xml_object, "BarCode").text = metadata_map[BAR_CODE]
    xml.etree.ElementTree.SubElement(xml_object, "ShelfLocation").text = metadata_map[SHELF]
    xml.etree.ElementTree.SubElement(xml_object, "Title").text = metadata_map[TITLE]
    xml.etree.ElementTree.SubElement(xml_object, "TranslatedTitle").text = metadata_map[TRANS_TITLE]
    xml.etree.ElementTree.SubElement(xml_object, "DateRangeStart").text = metadata_map[DATE_START]
    xml.etree.ElementTree.SubElement(xml_object, "DateRangeEnd").text = metadata_map[DATE_END]
    xml.etree.ElementTree.SubElement(xml_object, "DocumentSymbol").text = metadata_map[SYMBOL]
    xml.etree.ElementTree.SubElement(xml_object, "Section").text = metadata_map[SECTION]
    xml.etree.ElementTree.SubElement(xml_object, "Body").text = metadata_map[BODY]
    xml.etree.ElementTree.SubElement(xml_object, "Author").text = metadata_map[AUTHOR]
    xml.etree.ElementTree.SubElement(xml_object, "SalesPublication").text = metadata_map[SALES]
    xml.etree.ElementTree.SubElement(xml_object, "SalesPubNo").text = metadata_map[PUB_NO]
    xml.etree.ElementTree.SubElement(xml_object, "Language").text = metadata_map[LANGUAGE]
    xml.etree.ElementTree.SubElement(xml_object, "LOT").text = metadata_map[LOT]
    xml_request = xml.etree.ElementTree.tostring(xml_object, encoding='utf-8', xml_declaration=True)
    return xml_request


def create_package(folder, document, pdf_folder, csv_folder, jp2_folder, config):
    pdf_document_folder = os.path.join(pdf_folder, document)
    csv_document_folder = os.path.join(csv_folder, document)
    jp2_document_folder = os.path.join(jp2_folder, document)

    pdf_documents = [f.path for f in os.scandir(pdf_document_folder) if f.is_file()]
    csv_documents = [f.path for f in os.scandir(csv_document_folder) if f.is_file()]
    jp2_documents = [f.path for f in os.scandir(jp2_document_folder) if f.is_file()]

    assert len(pdf_documents) == 1
    assert len(csv_documents) == len(jp2_documents)

    export_folder = config['credentials']['export_folder']
    username = config['credentials']['username']
    bucket_name = config['credentials']['bucket']
    password = config['credentials']['password']
    server = config['credentials']['server']
    aeskey = config['credentials']['AESkey']
    parent_reference = config['credentials']['parent_reference']

    preservation_files_list = list()
    access_files_list = list()

    access_files_list.append(pdf_documents[0])
    all_files = 1
    for d in jp2_documents:
        preservation_files_list.append(d)
        all_files += 1

    callback = CSVFixityCallBack(csv_document_folder)

    identifiers = {"document": document}

    package_path = complex_asset_package(Title=document, Description=document, preservation_files_list=preservation_files_list,
                                         access_files_list=access_files_list, Identifiers=identifiers,
                                         export_folder=export_folder, parent_folder=folder,
                                         Preservation_files_fixity_callback=callback)
    print(package_path)

    access_key, secret_key, session_token, source_type, endpoint = session_key(server, bucket_name, username,
                                                                               password,
                                                                               aeskey)

    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                            aws_session_token=session_token)
    s3 = session.resource(service_name="s3")

    upload_key = str(uuid.uuid4())
    s3_object = s3.Object(bucket_name, upload_key)
    metadata = dict()
    metadata['key'] = upload_key
    metadata['name'] = upload_key + ".zip"
    metadata['bucket'] = bucket_name
    metadata['status'] = 'ready'
    metadata['collectionreference'] = parent_reference
    metadata['size'] = str(Path(package_path).stat().st_size)
    metadata['numberfiles'] = str(all_files)
    metadata['createdby'] = "python"

    metadata = {'Metadata': metadata}

    s3_object.upload_file(package_path, Callback=ProgressPercentage(package_path), ExtraArgs=metadata,
                          Config=transfer_config)


def main():
    config = configparser.ConfigParser()
    config.read('credentials.properties')
    csv_name = config['credentials']['csv.path']
    lot_path = config['credentials']['folder_root']
    security_tag = config['credentials']['security_tag']

    parent_folder_ref = config['credentials']['parent_reference']

    entity = EntityAPI()

    metadata = []
    with open(csv_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_dict = csv.DictReader(csv_file, delimiter=',')
        for item in csv_dict:
            metadata.append(item)
        print("Loaded %d rows of metadata from spreadsheet" % len(metadata))

    pdf_path = os.path.join(lot_path, "PDF")
    csv_path = os.path.join(lot_path, "CSV")
    jp2_path = os.path.join(lot_path, "JP2")
    assert os.path.exists(pdf_path)
    assert os.path.exists(csv_path)
    assert os.path.exists(jp2_path)

    for item in metadata:
        bar_code = item[BAR_CODE].strip()
        folder_name = str("0000" + bar_code).strip()
        folder_title = item[TITLE].strip()
        folder_description = item[SECTION].strip()
        pdf_folder = os.path.join(pdf_path, folder_name)
        csv_folder = os.path.join(csv_path, folder_name)
        jp2_folder = os.path.join(jp2_path, folder_name)
        if os.path.exists(pdf_folder) and os.path.exists(csv_folder) and os.path.exists(jp2_folder):
            print(f"Found {folder_name}")
            entities = entity.identifier(BAR_CODE, bar_code)
            if len(entities) == 0:
                folder = entity.create_folder(folder_title, folder_description, security_tag, parent_folder_ref)
                entity.add_identifier(folder, BAR_CODE, bar_code)
                xml_doc = get_metadata_doc(item)
                entity.add_metadata(folder, "https://archive.unog.ch/od", xml_doc.decode("utf-8"))
            else:
                folder = entity.folder(entities.pop().reference)
                fragment = entity.metadata_for_entity(folder, "https://archive.unog.ch/od")
                if fragment is None:
                    xml_doc = get_metadata_doc(item)
                    entity.add_metadata(folder, "https://archive.unog.ch/od", xml_doc.decode("utf-8"))

            documents = [f.name for f in os.scandir(pdf_folder) if f.is_dir()]
            for document in documents:
                print("\nChecking for existing document")
                entities = entity.identifier("document", document)
                if len(entities) == 0:
                    print(f"Starting Asset Creation.. {document}")
                    create_package(folder, document, pdf_folder, csv_folder, jp2_folder, config)
                else:
                    print(f"Skipping {document} already ingested.")


        else:
            print(f"Folder {folder_name} is missing, skipping....")
            continue


if __name__ == '__main__':
    main()
