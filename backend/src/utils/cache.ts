import NodeCache from "node-cache";

const cache = new NodeCache({ stdTTL: 3600 }); // Set default TTL to 1 hour

export default cache;
