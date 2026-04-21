import "dotenv/config";
async function run() {
  const res = await fetch("https://mail.sunilshahid.com/jmap", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Basic " + Buffer.from("sunilshahid:GF#YHeVUWWWm6ekNpt$DnC2PutnCknRUG8U$x9G&f6sF*BR^Wf").toString('base64'),
    },
    body: JSON.stringify({
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"],
      methodCalls: [
        ["Contact/get", { accountId: "p" }, "0"],
        ["ContactCard/get", { accountId: "p" }, "1"]
      ]
    })
  });
  console.log(await res.text());
}
run();
