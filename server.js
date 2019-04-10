const express = require("express");
const bodyParser = require("body-parser");
const { ApolloServer, gql } = require("apollo-server-express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const expressJWT = require("express-jwt");

const User = require("./models/User");

// Schema with typeDefs
const typeDefs = gql`
  type User {
    _id: ID!
    username: String!
    email: String!
    password: String!
  }

  type AuthPayload {
    token: String
    user: User
  }

  type Query {
    getUser: User
    login(email: String!, password: String!): AuthPayload
  }

  input UserInput {
    username: String!
    email: String!
    password: String!
  }

  type Mutation {
    signup(userInput: UserInput): AuthPayload
  }
`;

const resolvers = {
  Query: {
    getUser: async (parent, args, context) => {
      const user = context.user;
      if (!user) {
        throw new Error("Not authenticated");
      }

      return await User.findById(user.id);
    },

    login: async (parent, { email, password }) => {
      try {
        // Find if the user exists based on email
        const user = await User.findOne({ email });
        if (!user) {
          throw new Error("User does not exist.");
        }

        // Compare passwords
        const isEqual = await bcrypt.compare(password, user.password);
        if (!isEqual) {
          throw new Error("Password incorrect.");
        }

        // User has been found and password verified, create a JWT
        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );

        // Return the user and token
        return {
          token,
          user
        };
      } catch (err) {
        throw err;
      }
    }
  },

  Mutation: {
    signup: async (_, args) => {
      // Get inputs from arguments
      const { username, email, password } = args.userInput;

      try {
        // Find if user already exists
        const user = await User.findOne({ email });
        if (user) {
          throw new Error("User already exists.");
        }

        // Create a hashed password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create a new user according to schema
        const newUser = await new User({
          username,
          email,
          password: hashedPassword
        }).save();

        // Create saved user, do not return the password
        const savedUser = { ...newUser._doc, password: null };

        // Get a token from jwt
        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET
        );

        // Return user and token
        return { token, user: savedUser };
      } catch (err) {
        throw err;
      }
    }
  }
};

const app = express();

// Authentication middleware
app.use(
  expressJWT({
    secret: process.env.JWT_SECRET,
    credentialsRequired: false
  })
);

// Create Apollo Server with schema, resolvers, and context (which contains auth info)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => ({
    user: req.user
  })
});

server.applyMiddleware({ app, bodyParser });

const PORT = process.env.PORT || 4000;

// Connect Mongo Database
mongoose
  .connect(
    `mongodb+srv://${process.env.MONGO_USER}:${
      process.env.MONGO_PASSWORD
    }@cluster0-qlguq.mongodb.net/${process.env.MONGO_DB}?retryWrites=true`
  )
  .then(() => {
    app.listen({ port: PORT }, () =>
      console.log(`Server ready on PORT ${PORT}`)
    );
  })
  .catch(err => console.log("Database not connected", err));
