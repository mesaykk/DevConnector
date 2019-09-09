import {SET_CURRENT_USER , GET_ERRORS } from './types';
import axios from 'axios';
import setAuthToken from '../utils/setAuthtoken';
import jwt_decode from 'jwt-decode';



export const registerUser = (userData, history) => dispatch => {

      axios
          .post('api/users/register', userData)
          .then(res => history.push('/login'))
          .catch(err => 
               dispatch({
                   type: GET_ERRORS,
                   payload: err.response.data
               })
            );
}

export const setCurrentUser = decoded => {
    return {
        type: SET_CURRENT_USER,
        payload: decoded
    }
}

export const loginUser = userdata => dispatch => {
    axios.post('api/users/login', userdata)
             .then(res =>{
                 //Save to localstorage
               const {token} =res.data;

                 //Set token to ls
                  localStorage.setItem('jwtToken', token); 

                 //Set token to auth header
                 setAuthToken(token);

                 // Decode token to get user data
                const decoded = jwt_decode(token);
                 //set current user
                 dispatch(setCurrentUser(decoded))
               })
             .catch(err => 
                dispatch({
                    type: GET_ERRORS,
                    payload: err.response.data
                })
             );
}

export const logoutUser= () => dispatch => {
    //remove token from localstorage
   localStorage.removeItem('jwtToken');

    //Remove token auth headers
    setAuthToken(false);

    //Clean the user data from redux store // pass empty payload
    dispatch(setCurrentUser({}));
}
