# Copyright 2019 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""An AEAD implementation that forwards requests to a key managed by AWS KMS."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import binascii
from typing import Text

# Special imports
# import tink


class AwsKmsAead(object):
  """Forwards encryption/decryption requests to a key managed by AWS KMS.

  Associated data is stored under the key 'associatedData' in hexadecimal
  format, since AWS KMS expects a string -> string map.
  """

  def __init__(self, key_arn: Text, aws_client: 'botocore.client.KMS'):
    self._key_arn = key_arn
    self._aws_client = aws_client

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    hex_aad = binascii.hexlify(associated_data).decode('utf-8')

    response = self._aws_client.encrypt(
        KeyId=self._key_arn,
        Plaintext=plaintext,
        EncryptionContext={
            'associatedData': hex_aad,
        })

    return response['CiphertextBlob']
    # TODO(tanujdhir) Finish implementation

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    hex_aad = binascii.hexlify(associated_data).decode('utf-8')

    response = self._aws_client.decrypt(
        KeyId=self._key_arn,
        CiphertextBlob=plaintext,
        EncryptionContext={
            'associatedData': hex_aad,
        })

    return response['Plaintext']
    # TODO(tanujdhir) Finish implementation
