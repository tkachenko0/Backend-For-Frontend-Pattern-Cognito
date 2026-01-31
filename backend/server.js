import express from "express";

const app = express();
const port = 4000;

app.use(express.json());

app.get("/user", (req, res) => {
  const userSub = req.headers["x-user-sub"];
  const userEmail = req.headers["x-user-email"];
  const customGroups = req.headers["x-user-custom-groups"];
  const cognitoGroups = req.headers["x-user-cognito-groups"];
  const cognitoUsername = req.headers["x-user-cognito-username"];

  if (!userSub) {
    return res.status(401).send({ error: "Unauthorized" });
  }

  res.send({
    message: "User data from backend",
    user: {
      sub: userSub,
      email: userEmail,
      customGroups: customGroups,
      cognitoGroups: cognitoGroups,
      cognitoUsername: cognitoUsername,
    },
    allHeaders: Object.keys(req.headers)
      .filter((h) => h.startsWith("x-user-"))
      .reduce((acc, h) => {
        acc[h] = req.headers[h];
        return acc;
      }, {}),
  });
});

let counter = 0;

app.get("/counter", (_, res) => {
  res.send({ counter });
});

app.post("/counter/increment", (_, res) => {
  counter++;
  res.send({ counter, message: "Counter incremented" });
});

app.get("/protected", (req, res) => {
  const userSub = req.headers["x-user-sub"];
  if (!userSub) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  res.send({ message: "This is protected data from backend" });
});

app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
