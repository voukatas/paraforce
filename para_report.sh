echo ""
cat $1|grep "Success Req:"
cat $1|grep "Total Requests:"
echo ""
echo "--------------------"
echo ""
#Total time:
cat $1|grep "Total time:"
echo "--------------------"
echo ""
echo "socket timer related"
echo "--------------------"
no_sess=$(grep -c "No existing session" $1)
echo "No existing session: $no_sess"

time_out=$(grep -c "timed out" $1)
echo "Timeouts: $time_out"

conn_rst=$(grep -c "Connection reset by peer" $1)
echo "Conn Resets: $conn_rst"

echo ""
socket_timer_sum=$(($no_sess+$time_out+$conn_rst))
echo "Sum of all above: $socket_timer_sum"
echo "--------------------"

echo ""
echo "banner timer related"
echo "--------------------"
banner_err=$(grep -c "Error reading SSH protocol banner" $1)
echo "Banner Error: $banner_err"

retries_num=$(grep -c "Retry #" $1)
echo "Retries: $retries_num"
echo "--------------------"

echo ""
echo "Informational"
echo "--------------------"
auth_exception_num=$(grep -c "AUTH Exception" $1)
echo "AUTH Exception: $auth_exception_num"