const express = require("express");

require("dotenv").config();
const app = express();

const jwt = require("jsonwebtoken");

app.use(express.json());

const api = require("./config/prisma");

const bcrypt = require("bcrypt");

app.use(express.urlencoded({ extended: false }));

//AUTH PART
function auth(req, res, next) {
  console.log("Hii this is middleware");
  next();
}

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send("Please send email and password");
    }

    const user = await api.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(400).send("Email does not exist");
    }

    const isMatch = bcrypt.compareSync(password, user.password);

    if (!isMatch) {
      return res.status(400).send("Wrong password");
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.MYSECRET,
      {
        expiresIn: "48h",
      },
    );

    return res.json({
      token,
      message: "You are logged in",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: error.message,
    });
  }
});

//home page

app.get("/", async (req, res) => {
  try {
    const totalusers = await api.user.count();
    const user = await api.user.findMany()
    console.log(user)
    return res.json({ message: `Total users are ${totalusers}` ,user});
  } catch (error) {
    console.error(error)
    return res.status(500).send(error.message);
  }

});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) {
      return res.send("Please send name,email and password");
    }
    const userExist = await api.user.findFirst({
      where: {
        OR: [{ email }, { phone }]
      }
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
    console.log("request found signup ");
    return res.send({
      message:
        "Welcome Your sign up is successfull complete now you are authorized to access the application",
      data: user,
    });
  } catch (error) {
    console.error("Signup Error :",error)
    return res.status(500).json({message : error.message})
  }
});

app.get("/secretRoute", auth, (req, res) => {
  res.send("my secret route");
});

app.listen(process.env.PORT || 3000, () => {
  console.log(
    `Your Server is Running on PORT no http://localhost:${process.env.PORT || 3000}`,
  );
});
