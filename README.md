# E-Voty-IT325-Web-Services-Final-Project
README

This is a project that utilizes the Flask framework to build a web application for an election. It uses SQLAlchemy for database management and Marshmallow for serialization and deserialization of objects. It also uses the Flask JWT extended library for user authentication and authorization.

The project consists of two models: User and Candidate. The User model represents a user of the application and has fields for storing their username, password, email, first and last name, governate, electoral circle, and whether or not they have voted. The Candidate model represents a candidate running in the election and has fields for storing their name, governate, and electoral circle.

The project includes routes for creating and retrieving users, as well as routes for voting and checking if a user has already voted. It also includes a route for sending a confirmation email to the user after they have voted.

Before the first request is made to the application, the create_tables function is called which creates the necessary tables in the database.

To run the project, you will need to have Flask and the other required libraries installed. You can install these by running pip install -r requirements.txt in the project directory. You will also need to set up the SMTP server in the send_confirmation_email function to be able to send the confirmation emails.
