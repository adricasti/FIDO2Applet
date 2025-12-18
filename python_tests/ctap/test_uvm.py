from typing import Optional, Any, Dict

from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import Ctap2Extension, RegistrationExtensionProcessor, AuthenticationExtensionProcessor
from fido2.webauthn import UserVerificationRequirement

from .ctap_test import CTAPTestCase, FixedPinUserInteraction


class UVMExtension(Ctap2Extension):

    NAME = 'uvm'

    def is_supported(self) -> bool:
        return True

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if inputs.get(self.NAME) or inputs.get("uvm"):
            class Processor(RegistrationExtensionProcessor):
                def prepare_inputs(self, pin_token):
                    return {UVMExtension.NAME: True}

                def prepare_outputs(self, response, pin_token):
                    extensions = response.auth_data.extensions or {}
                    return {"uvm": extensions.get(UVMExtension.NAME)}

            return Processor()
        return None

    def get_assertion(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if inputs.get(self.NAME) or inputs.get("uvm"):
            class Processor(AuthenticationExtensionProcessor):
                def prepare_inputs(self, selected, pin_token):
                    return {UVMExtension.NAME: True}

                def prepare_outputs(self, response, pin_token):
                    extensions = response.auth_data.extensions or {}
                    return {"uvm": extensions.get(UVMExtension.NAME)}

            return Processor()
        return None
        

class UVMTestCase(CTAPTestCase):

    def test_uvm_no_pin_on_makecred(self):
        res = self.ctap2.make_credential(**self.basic_makecred_params, extensions={
            "uvm": True
        })
        self.assertEqual([[1, 10, 4]], res.auth_data.extensions['uvm'])

    def test_uvm_with_pin_on_makecred(self):
        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension],
                                            user_interaction=FixedPinUserInteraction(pin))
        cred = client.make_credential(
            self.get_high_level_make_cred_options(
                user_verification=UserVerificationRequirement.REQUIRED,
                extensions={"uvm": True}
            )
        )

        self.assertEqual([[2048, 10, 4]], cred.client_extension_results['uvm'])

    def test_uvm_with_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options())

        pin = "12345"
        ClientPin(self.ctap2).set_pin(pin)

        client = self.get_high_level_client(extensions=[UVMExtension],
                                            user_interaction=FixedPinUserInteraction(pin))

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred,
            user_verification=UserVerificationRequirement.REQUIRED,
            extensions={"uvm": True}
        ))

        self.assertEqual([[2048, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])

    def test_uvm_without_pin_on_get_assertion(self):
        cred = self.get_high_level_client().make_credential(self.get_high_level_make_cred_options())

        client = self.get_high_level_client(extensions=[UVMExtension])

        assertion = client.get_assertion(self.get_high_level_assertion_opts_from_cred(
            cred,
            extensions={"uvm": True}
        ))

        self.assertEqual([[1, 10, 4]],
                         assertion.get_assertions()[0].auth_data.extensions['uvm'])
