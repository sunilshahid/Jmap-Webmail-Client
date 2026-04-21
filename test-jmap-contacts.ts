async function test() {
  const token = 'GF#YHeVUWWWm6ekNpt$DnC2PutnCknRUG8U$x9G&f6sF*BR^Wf';
  const url = 'https://mail.sunilshahid.com/jmap';
  const auth = 'Basic ' + Buffer.from('sunilshahid:' + token).toString('base64');
  
  const body = {
    using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"],
    methodCalls: [
      [
        "ContactCard/set",
        {
          accountId: "p",
          destroy: ["c"]
        },
        "0"
      ]
    ]
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': auth
      },
      body: JSON.stringify(body)
    });
    
    console.log(await res.text());
  } catch (e) {
    console.error(e);
  }
}

test();
