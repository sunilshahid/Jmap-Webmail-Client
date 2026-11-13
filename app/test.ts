import "dotenv/config";

async function run() {
  const jmapUrl = process.env.JMAP_URL || "https://mail.example.com/jmap";
  const username = process.env.JMAP_USERNAME || "";
  const password = process.env.JMAP_PASSWORD || "";

  if (!username || !password) {
    console.error("Missing JMAP_USERNAME or JMAP_PASSWORD in environment variables.");
    process.exit(1);
  }

  const res = await fetch(jmapUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Basic " + Buffer.from(`${username}:${password}`).toString('base64'),
    },
    body: JSON.stringify({
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"],
      methodCalls: [
        ["ContactCard/get", { accountId: "p" }, "0"]
      ]
    })
  });
  console.log(await res.text());
}
run();
