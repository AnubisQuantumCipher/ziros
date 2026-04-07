export interface MailboxNetworkDeployment {
  contractAddress: string | null;
  compiledArtifactDir: string;
  status: "pending-deployment" | "deployed" | "retired";
  txHash?: string;
  deployedAt?: string;
  explorerUrl?: string;
}

export interface MailboxDeploymentManifest {
  schema: "ziros-wallet-mailbox-deployment-v1";
  contractName: "ziros_wallet_mailbox";
  description: string;
  networks: {
    preprod: MailboxNetworkDeployment;
    preview: MailboxNetworkDeployment;
  };
  notes: string[];
}
