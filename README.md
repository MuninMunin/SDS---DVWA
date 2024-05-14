# DVWA - SQL Injection & XSS (Cross Site Scripting)

# SQL Injection

### What is SQL Injection?

SQL Injection is a type of web security vulnerability that allows an attacker to manipulate an application's database query by inserting malicious SQL code into input fields, leading to unauthorized access or data manipulation.

### Basic Principles of SQL Injection

SQL Injection typically occurs when an application directly embeds user input into SQL queries without sufficient validation or sanitization. When an application incorporates user input as part of an SQL statement, an attacker can craft specific inputs to alter the final SQL statement to achieve their goals, such as bypassing authentication, reading, or modifying database data.

### Example

Suppose there is a simple login form where a user inputs a username and password, and the system executes the following SQL query to verify the user's identity:

```sql
SELECT * FROM users WHERE username = 'user input username' AND password = 'user input password';
```

If the user inputs the following:

- Username: `admin`
- Password: `' OR '1'='1`

The generated SQL statement would become:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';

```

Since `'1'='1'` is always true, this query will return information for all users in the database, allowing the attacker to bypass authentication and log in to the system.

---

<img width="943" alt="Screenshot 2024-05-14 at 3 42 56 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/9e23f1c0-361e-44a1-861c-f1b0baa2c69d">

### DVWA SQL Injection - Low level

1. **View Source Code**:
    
    ```php
    <?php
    
    if( isset( $_REQUEST[ 'Submit' ] ) ) { 
        // Get input
        $id = $_REQUEST[ 'id' ];
    
        // Check database
        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"; 
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
    
        // Get results
        while( $row = mysqli_fetch_assoc( $result ) ) {
            // Get values
            $first = $row["first_name"];
            $last  = $row["last_name"];
    
            // Feedback for end user
            echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>"; 
        }
        mysqli_close($GLOBALS["___mysqli_ston"]);
    }
    ?>
    ```
    
2. **Source code Analysis**:
    - The server-side `low.php`  script doesn’t perform any check or filtering on user’s id input and directly displays the execution result of the SQL query to the client-side.
    - Try input `' OR '1'='1`  it returns all the result of user’s first name and surname. With that experiment It doesn’t return errors, So we have chance to get database information through SQL injection.
        
        <img width="941" alt="Screenshot 2024-05-14 at 3 55 35 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/5e91e4cc-1c05-47c7-93e4-67fc4f64139b">

        
      
        
3. **Vulnerabilities Exploitation**:
    - **The vulnerable script:** `"SELECT first_name, last_name FROM users WHERE user_id = '$id';"`
    - **Get the usernames and passwords from database :**  `’ UNION SELECT user, password FROM users#`
        <img width="931" alt="Untitled" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/dec7790e-0f67-4c5c-9156-00aea2b19431">
        
    - **Crack the hash:** Even though passwords are hashed but still try to crack it with library attack.
        <img width="850" alt="Screenshot_2024-05-14_at_7 47 39_in_the_evening" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/58f34eb1-ae2b-48c5-bb52-4e0d4c824e8d">      

---

### DVWA SQL Injection - Medium level

1. **View Source Code**:
    
    ```php
    <?php
    
    if( isset( $_POST[ 'Submit' ] ) ) {
    	// Get input
    	$id = $_POST[ 'id' ];
    
    	$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
    
    	$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
    	$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );
    
    	// Get results
    	while( $row = mysqli_fetch_assoc( $result ) ) {
    		// Display values
    		$first = $row["first_name"];
    		$last  = $row["last_name"];
    
    		// Feedback for end user
    		$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    	}
    
    }
    
    // This is used later on in the index.php page
    // Setting it here so we can close the database connection in here like in the rest of the source scripts
    $query  = "SELECT COUNT(*) FROM users;";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
    $number_of_rows = mysqli_fetch_row( $result )[0];
    
    mysqli_close($GLOBALS["___mysqli_ston"]);
    ?>
    ```
    
2. **Source code Analysis**:
    - `medium.php`  script try to avoid user input by giving dropdown selection instead.
    - It is still able to change the script in `inspect element`
        
        ![Screenshot 2024-05-14 at 8.15.46 in the evening.png](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Screenshot_2024-05-14_at_8.15.46_in_the_evening.png)
        
3. **Vulnerabilities Exploitation**:
    - **Get the usernames and passwords from database :**  edit in inspector mode by inserting script as in the picture below:
        
        ![Untitled](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Untitled%202.png)
        
    - **Submit:**
        
        ![Untitled](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Untitled%203.png)
        

---

### DVWA SQL Injection - High level

1. **View Source Code**:
    
    ```php
    <?php
    
    if( isset( $_SESSION [ 'id' ] ) ) {
    	// Get input
    	$id = $_SESSION[ 'id' ];
    
    	// Check database
    	$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
    	$result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );
    
    	// Get results
    	while( $row = mysqli_fetch_assoc( $result ) ) {
    		// Get values
    		$first = $row["first_name"];
    		$last  = $row["last_name"];
    
    		// Feedback for end user
    		$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    	}
    
    	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
    }
    
    ?>
    ```
    
2. **Source code Analysis**:
    - `High.php`  script want to avoid direct input so it call new popup window for input, from source code can be seen that it is very similar to low-level but it is different here with `LIMIT 1;` in the query.
    - However, still can do `’ UNION SELECT user, password FROM users#` use the hashtag to ignore the condition.
        
        ![Screenshot 2024-05-15 at 12.21.10 at night.png](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Screenshot_2024-05-15_at_12.21.10_at_night.png)
        
3. **Vulnerabilities Exploitation**:
    - **Submit:**
        
        ![Untitled](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Untitled%204.png)
        

---

**As proof here is the entire screen in my laptop:** 

- As can be seen, the background is my desktop wallpaper.
- In about, it displays my name.
- The top bar can see the date 14, May, 8:27PM and compare to the name of screenshot (the same date, similar time because i just did it at the moment.
- The navigation bar on the middle-right are from my screen.
- Look at another window behind setting and finder, that is kali VM is running and I was testng on it.
    
    ![Untitled](DVWA%20-%20SQL%20Injection%20&%20XSS%20(Cross%20Site%20Scripting)%209aab62f0a00d4a00a8204ace8cb479c4/Untitled%205.png)
