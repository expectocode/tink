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
import tink


class AwsKmsAead(tink.Aead):
  """Authenticated encryption with associated data (see base class).

  An implementation of AEAD that forwards encryption/decryption requests to a
  key managed by AWS KMS.

  Associated data is stored under the key 'associatedData' in
  hexadecimal-encoded format, since AWS KMS expects a string -> string map.
  """

  def __init__(self, key_arn: Text, aws_client: 'botocore.client.KMS'):
    """Initialises an AwsKmsAead.

    Args:
      key_arn: Amazon Resource Name of a crypto key in AWS KMS, without the
        aws-mks:// prefix.
      aws_client: AWS KMS Client object of the correct region.
    """
    self._key_arn = key_arn
    self._aws_client = aws_client

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypts plaintext with associated_data (see base class).

    Encryption is performed using this object's AWS KMS client.
    """
    hex_aad = binascii.hexlify(associated_data).decode('utf-8')

    response = self._aws_client.encrypt(
        KeyId=self._key_arn,
        Plaintext=plaintext,
        EncryptionContext={
            'associatedData': hex_aad,
        })

    return response['CiphertextBlob']
    # TODO(tanujdhir) Error handling

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Decrypts plaintext with associated_data (see base class).

    Decryption is performed using this object's AWS KMS client.
    """
    hex_aad = binascii.hexlify(associated_data).decode('utf-8')

    response = self._aws_client.decrypt(
        CiphertextBlob=ciphertext,
        EncryptionContext={
            'associatedData': hex_aad,
        })

    return response['Plaintext']
    # TODO(tanujdhir) Error handling
