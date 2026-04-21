async function test() {
  const token = 'GF#YHeVUWWWm6ekNpt$DnC2PutnCknRUG8U$x9G&f6sF*BR^Wf';
  const url = 'https://mail.sunilshahid.com/jmap';
  const auth = 'Basic ' + Buffer.from('sunilshahid:' + token).toString('base64');
  
  const body = {
    using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
    methodCalls: [
      [
        "Calendar/get",
        {
          accountId: "p"
        },
        "0"
      ]
    ]
  };

  try {
    let res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
      body: JSON.stringify(body)
    });
    
    const calendars = await res.json();
    const calendarId = calendars.methodResponses[0][1].list[0].id;
    console.log("Calendar ID:", calendarId);

    const createBody = {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
      methodCalls: [
        [
          "CalendarEvent/set",
          {
            accountId: "p",
            create: {
              "new_event_1": {
                "@type": "Event",
                "uid": "123456789",
                "calendarIds": { [calendarId]: true },
                "priority": 5,
                "created": "2024-04-21T00:00:00Z",
                "start": "2026-04-22T10:00:00Z",
                "duration": "PT1H",
                "title": "Test event"
              }
            }
          },
          "0"
        ]
      ]
    };

    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
      body: JSON.stringify(createBody)
    });

    console.log(await res.text());

  } catch (e) {
    console.error(e);
  }
}

test();
