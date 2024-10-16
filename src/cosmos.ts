import { CosmosClient } from '@azure/cosmos';

const endpoint: string = process.env.COSMOS_DB_ENDPOINT || 'YOUR_COSMOS_DB_ENDPOINT';
const key: string = process.env.COSMOS_DB_KEY || 'YOUR_COSMOS_DB_KEY';
const databaseId: string = 'your-database-id';
const containerId: string = 'your-container-id';

const client = new CosmosClient({ endpoint, key });

// Define an interface for the invitation structure
interface Invitation {
  id: string;
  invitationCode: string;
  email: string;
  createdTime: string;
  ttl: number;
}

// Function to store invitation code in Cosmos DB
async function storeInvitationCode(invitationCode: string, email: string): Promise<void> {
  const container = client.database(databaseId).container(containerId);
  const ttl = 3600; // 1 hour
  const invitation: Invitation = {
    id: invitationCode,
    invitationCode: invitationCode,
    email: email,
    createdTime: new Date().toISOString(),
    ttl: ttl,
  };

  await container.items.create(invitation);
  console.log('Invitation code stored:', invitation);
}

// Function to verify invitation code in Cosmos DB
async function verifyInvitationCode(invitationCode: string): Promise<boolean> {
  const container = client.database(databaseId).container(containerId);
  const { resource: invitation } = await container.item(invitationCode, invitationCode).read();

  if (invitation) {
    console.log('Valid invitation code:', invitation);
    return true;
  } else {
    console.log('Invalid or expired invitation code.');
    return false;
  }
}
