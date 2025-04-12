from __future__ import annotations

import datetime
import json
import secrets
import string

import oci

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Oracle Cloud output
    """

    def generate_random_log_id(self):
        charset = string.ascii_letters + string.digits
        random_log_id = "".join(secrets.choice(charset) for _ in range(32))
        return f"cowrielog-{random_log_id}"

    def sendLogs(self, event):
        log_id = self.generate_random_log_id()
        # Initialize service client with default config file
        current_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self.log_ocid = CowrieConfig.get("output_oraclecloud", "log_ocid")
        self.hostname = CowrieConfig.get("honeypot", "hostname")

        try:
            # Send the request to service, some parameters are not required, see API
            # doc for more info
            self.loggingingestion_client.put_logs(
                log_id=self.log_ocid,
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="1.0",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data=event,
                                    id=log_id,
                                    time=current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                )
                            ],
                            source=self.hostname,
                            type="cowrie",
                        )
                    ],
                ),
                timestamp_opc_agent_processing=current_time.strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
            )
        except oci.exceptions.ServiceError as ex:
            log.err(
                f"Oracle Cloud plugin Error: {ex.message}\n"
                + f"Oracle Cloud plugin Status Code: {ex.status}\n"
            )
        except Exception as ex:
            log.err(f"Oracle Cloud plugin Error: {ex}")
            raise

    def start(self):
        """
        Initialize Oracle Cloud LoggingClient with user or instance principal authentication
        """
        authtype = CowrieConfig.get("output_oraclecloud", "authtype")

        if authtype == "instance_principals":
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()

            # In the base case, configuration does not need to be provided as the region and tenancy are obtained from the InstancePrincipalsSecurityTokenSigner
            # identity_client = oci.identity.IdentityClient(config={}, signer=signer)
            self.loggingingestion_client = oci.loggingingestion.LoggingClient(
                config={}, signer=signer
            )

        elif authtype == "user_principals":
            tenancy_ocid = CowrieConfig.get("output_oraclecloud", "tenancy_ocid")
            user_ocid = CowrieConfig.get("output_oraclecloud", "user_ocid")
            region = CowrieConfig.get("output_oraclecloud", "region")
            fingerprint = CowrieConfig.get("output_oraclecloud", "fingerprint")
            keyfile = CowrieConfig.get("output_oraclecloud", "keyfile")

            config_with_key_content = {
                "user": user_ocid,
                "key_file": keyfile,
                "fingerprint": fingerprint,
                "tenancy": tenancy_ocid,
                "region": region,
            }
            oci.config.validate_config(config_with_key_content)
            self.loggingingestion_client = oci.loggingingestion.LoggingClient(
                config_with_key_content
            )
        else:
            log.msg(
                "output_oraclecloud.authtype must be instance_principals or user_principals"
            )
            raise ValueError()

    def stop(self):
        pass

    def write(self, event):
        """
        Push to Oracle Cloud put_logs
        """
        # Add the entry to redis
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]
        self.sendLogs(json.dumps(event))
