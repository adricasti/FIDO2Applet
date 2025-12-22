import secrets
import unittest
from typing import Optional

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, PinProtocolV2
from fido2.ctap2.base import args as ctap_args

from .ctap_test import CTAPTestCase


class EnterpriseAttestationRPFilteringTestCase(CTAPTestCase):
    """
    Tests for CTAP 2.2 enterprise attestation with RP filtering
    """

    cp: ClientPin

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        super().setUp(install_params=install_params)
        self.reset()

    def reset(self):
        super().reset()
        self.cp = ClientPin(self.ctap2)

    def enable_enterprise_attestation_for_rps(self, rp_ids):
        """
        Helper to enable enterprise attestation for specific RP IDs
        """
        # Build CBOR map with rpIds array
        # Format: A1 01 8X [rpid strings]
        import cbor2
        params = cbor2.dumps({0x01: rp_ids})
        
        # Send authenticatorConfig command with enableEnterpriseAttestation
        self.ctap2.send_cbor(
            0x0D,  # authenticatorConfig
            ctap_args({
                0x01: 0x01,  # subCommand: enableEnterpriseAttestation
                0x02: params  # subCommandParams
            })
        )

    def test_ep_option_false_by_default(self):
        """EP option should be false when no RPs are configured"""
        info = self.ctap2.get_info()
        self.assertFalse(info.options.get("ep", False))

    def test_enable_enterprise_attestation_for_single_rp(self):
        """Enable enterprise attestation for a single RP"""
        self.enable_enterprise_attestation_for_rps(["example.com"])
        
        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("ep"))

    def test_enable_enterprise_attestation_for_multiple_rps(self):
        """Enable enterprise attestation for multiple RPs"""
        self.enable_enterprise_attestation_for_rps(["example.com", "test.org", "corp.example"])
        
        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("ep"))

    def test_enterprise_attestation_rejected_for_non_configured_rp(self):
        """Enterprise attestation should be rejected for RPs not in allowlist"""
        # Enable for one RP
        self.enable_enterprise_attestation_for_rps(["allowed.example.com"])
        
        # Try to use enterprise attestation with a different RP
        self.basic_makecred_params["rp"]["id"] = "notallowed.example.com"
        self.basic_makecred_params["enterprise_attestation"] = 1
        
        with self.assertRaises(CtapError) as e:
            self.ctap2.make_credential(**self.basic_makecred_params)
        
        # Should get UNAUTHORIZED_PERMISSION error
        self.assertEqual(CtapError.ERR.UNAUTHORIZED_PERMISSION, e.exception.code)

    def test_enterprise_attestation_accepted_for_configured_rp(self):
        """Enterprise attestation should work for RPs in allowlist"""
        rp_id = "allowed.example.com"
        self.enable_enterprise_attestation_for_rps([rp_id])
        
        self.basic_makecred_params["rp"]["id"] = rp_id
        self.basic_makecred_params["enterprise_attestation"] = 1
        
        # Should succeed
        result = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertIsNotNone(result)

    def test_disable_enterprise_attestation(self):
        """Disabling enterprise attestation should clear all RPs"""
        # Enable for some RPs
        self.enable_enterprise_attestation_for_rps(["example.com", "test.org"])
        
        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("ep"))
        
        # Disable by sending empty params
        self.ctap2.send_cbor(
            0x0D,  # authenticatorConfig
            ctap_args({
                0x01: 0x01,  # subCommand: enableEnterpriseAttestation
            })
        )
        
        info = self.ctap2.get_info()
        self.assertFalse(info.options.get("ep", False))

    def test_enterprise_attestation_limit_exceeded(self):
        """Should reject when trying to configure more than MAX RPs"""
        # Try to configure 4 RPs (max is 3)
        with self.assertRaises(CtapError) as e:
            self.enable_enterprise_attestation_for_rps([
                "rp1.example.com",
                "rp2.example.com", 
                "rp3.example.com",
                "rp4.example.com"
            ])
        
        self.assertEqual(CtapError.ERR.LIMIT_EXCEEDED, e.exception.code)

    def test_enterprise_attestation_cleared_on_reset(self):
        """Enterprise attestation RPs should be cleared on authenticator reset"""
        self.enable_enterprise_attestation_for_rps(["example.com"])
        
        info = self.ctap2.get_info()
        self.assertTrue(info.options.get("ep"))
        
        # Reset authenticator
        self.reset()
        
        info = self.ctap2.get_info()
        self.assertFalse(info.options.get("ep", False))

    def test_enterprise_attestation_without_parameter_uses_basic(self):
        """When enterprise attestation is not requested, basic attestation should be used"""
        self.enable_enterprise_attestation_for_rps(["example.com"])
        
        # Make credential without enterprise_attestation parameter
        self.basic_makecred_params["rp"]["id"] = "example.com"
        # Don't set enterprise_attestation parameter
        
        result = self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertIsNotNone(result)


class CTAP22VersionTestCase(CTAPTestCase):
    """
    Tests for CTAP 2.2 version reporting
    """

    def test_fido_2_2_in_versions(self):
        """getInfo should include FIDO_2_2 in versions array"""
        info = self.ctap2.get_info()
        self.assertIn("FIDO_2_2", info.versions)

    def test_fido_2_1_still_supported(self):
        """FIDO_2_1 should still be supported for backwards compatibility"""
        info = self.ctap2.get_info()
        self.assertIn("FIDO_2_1", info.versions)
        self.assertIn("FIDO_2_0", info.versions)


if __name__ == '__main__':
    unittest.main()
