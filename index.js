const express = require("express");

require("dotenv").config();
const app = express();

app.use(express.json());

const api = require("./config/prisma");

const bcrypt = require("bcrypt");

//home page

app.get("/", async (req, res) => {
    const user = await api.user.findMany();
    res.send(user)
  try {
    const totalusers = await api.user.count();
    if (totalusers) {
      return res.send(`total users are ${totalusers}`);
    } else {
      return res.send("does not exist");
    }
  } catch (error) {
    return res.send(error);
  }
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) {
      return res.send("Please send name,email and password");
    }
    const userExist = await api.user.findUnique({
      where: {
        email: email,
        phone: phone,
      },
    });

    if (userExist) {
      return res.send(`User Already Exist with this email and phone`);
    }

    const passHash = bcrypt.hashSync(password, 10);

    const user = await api.user.create({
      data: {
        name,
        email,
        password: passHash,
        phone,
      },
    });
    return res.send({
      message:
        "Welcome Your sign up is successfull complete now you are authorized to access the application",
      data: user,
    });
  } catch (error) {
    return res.send(error);
  }
});
app.listen(process.env.PORT || 3000, () => {
  console.log(
    `Your Server is Running on PORT no http://localhost:${process.env.PORT || 3000}`,
  );
});
