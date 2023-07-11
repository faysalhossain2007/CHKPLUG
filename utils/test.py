import re

sqlstring = '"UPDATE  $wpdb->users SET user_login = %s WHERE user_login = %s", $new_username, $old_username'
sqlstring = f"$'{sqlstring}'"
print(sqlstring)

sql = re.sub(r"\s+", " ", sqlstring)


print(sql)