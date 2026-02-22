# Sleep Diary

## Project Description
Sleep Diary is a tool designed to help users track and analyze their sleep patterns. By logging sleep hours and assessing the quality of sleep, users can make informed decisions to improve their overall health and well-being.

## Installation
To install Sleep Diary, follow these steps:
1. Clone the repository: `git clone https://github.com/josepantufatavares/sleep-diary.git`
2. Navigate to the project directory: `cd sleep-diary`
3. Install the required dependencies: `npm install` (or the package manager of your choice).

## Setup
Ensure your environment is set up properly:  
- Node.js version: `>=12.0.0`  
- npm version: `>=6.0.0`  

## API Documentation
The API allows users to manage their sleep logs with the following endpoints:

- `GET /api/sleep-logs` - Retrieve all sleep logs.
- `POST /api/sleep-logs` - Create a new sleep log.
- `PUT /api/sleep-logs/:id` - Update an existing sleep log.
- `DELETE /api/sleep-logs/:id` - Delete a sleep log.

### Example Request  
```json  
{  
  "hoursSlept": 7,
  "sleepQuality": "Good"
}  
```

## Usage Examples
To log a new sleep entry, send a POST request to `/api/sleep-logs` with the sleep data in the request body. You can access existing logs using a GET request to the same endpoint.

## Deployment Instructions
To deploy the Sleep Diary application, consider using services such as:
1. Heroku  
2. Vercel  
3. AWS Elastic Beanstalk  

Refer to each service's documentation for specific deployment instructions. 

## Contributing
Please read the [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.  
