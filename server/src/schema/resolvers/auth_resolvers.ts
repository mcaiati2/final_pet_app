// Importing the dotenv package to load environment variables from a .env file into process.env
import dotenv from 'dotenv';
// Importing the jsonwebtoken package to handle JWT creation and verification
import jwt from 'jsonwebtoken';
// Importing Types from mongoose to use ObjectId type
import { Types } from 'mongoose';
// Importing GraphQLError from graphql to handle GraphQL errors
import { GraphQLError } from 'graphql';

// Loading environment variables from the .env file
dotenv.config();

// Importing UserInterface from the interfaces directory to define the structure of a User object
import UserInterface from '../../interfaces/User';
// Importing Context from the interfaces directory to define the structure of the context object
import Context from '../../interfaces/Context';
// Importing the User model from the models directory to interact with the User collection in the database
import User from '../../models/User.js';

// Importing the errorHandler function from the helpers directory to handle errors
import { errorHandler } from '../helpers/index.js';

// Destructuring the sign function from the jsonwebtoken package
const { sign } = jwt;

/**
 * Function to create a JWT token for a given user ID
 */
function createToken(user_id: Types.ObjectId) {
  // Check if JWT_SECRET is defined in the environment variables
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined');
  }
  // Create and return a signed JWT token with the user_id payload
  return sign({ user_id: user_id }, process.env.JWT_SECRET);
}

// Defining the auth_resolvers object to handle GraphQL queries and mutations related to authentication
const auth_resolvers = {
  Query: {
   
    async getUser(_: any, __: any, context: Context) {
      // Check if the user is authenticated
      if (!context.req.user) {
        return {
          user: null
        }
      }

      // Return the authenticated user
      return {
        user: context.req.user
      }
    }
  },

  Mutation: {
    /***  
     *** AUTH RESOLVERS *** 
    ***/

    async registerUser(_: any, args: { username: string; email: string; password: string; }, context: Context) {
      try {
        // Create a new user with the provided arguments
        const user = await User.create(args);

        // Create a JWT token for the new user
        const token = createToken(user._id);
        // Set the JWT token as a cookie in the response
        context.res.cookie('pet_token', token, {
          httpOnly: true,
          secure: process.env.PORT ? true : false,
          sameSite: true
        });

        // Return the newly created user
        return {
          user: user
        };
      } catch (error: any) {
        // Handle any errors that occur during user creation
        const errorMessage = errorHandler(error);

        // Throw a GraphQL error with the error message
        throw new GraphQLError(errorMessage);
      }
    },

    /**
     * Resolver to log a user in
     * @param _ - Unused parameter
     * @param args - The arguments containing email and password
     * @param context - The context object containing the request and response
     * @returns The logged-in user
     */
    async loginUser(_: any, args: { email: string; password: string; }, context: Context) {
      // Find the user by email
      const user: UserInterface | null = await User.findOne({
        email: args.email
      });

      // If no user is found, throw a GraphQL error
      if (!user) {
        throw new GraphQLError('No user found with that email address')
      }

      // Validate the provided password
      const valid_pass = await user.validatePassword(args.password);

      // If the password is incorrect, throw a GraphQL error
      if (!valid_pass) {
        throw new GraphQLError('Password is incorrect')
      }

      // Create a JWT token for the user
      const token = createToken(user._id!);

      // Set the JWT token as a cookie in the response
      context.res.cookie('pet_token', token, {
        httpOnly: true,
        secure: process.env.PORT ? true : false,
        sameSite: true
      });

      // Return the logged-in user
      return {
        user: user
      }
    },

   
    logoutUser(_: any, __: any, context: Context) {
      // Clear the JWT token cookie from the response
      context.res.clearCookie('pet_token');

      // Return a success message
      return {
        message: 'Logged out successfully!'
      }
    }
  }
};

// Exporting the auth_resolvers object as the default export
export default auth_resolvers;