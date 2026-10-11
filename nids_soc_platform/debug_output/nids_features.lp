\* Source Pyomo model name=NIDS_Feature_Selection_MIP *\

min 
objective:
-1.438301579527785 z(Flow_Duration)
-0.9383015795277849 z(Total_Fwd_Packets)
-0.5567692944911506 z(Total_Backward_Packets)
-0.9383015795277849 z(Flow_Bytes_s)
-0.9383015795277849 z(Flow_Packets_s)
+2.0164045625291123 w(Flow_Duration_Total_Fwd_Packets)
+1.2635237068544238 w(Flow_Duration_Total_Backward_Packets)
+2.046042457912228 w(Flow_Duration_Flow_Bytes_s)
+2.044795598071847 w(Flow_Duration_Flow_Packets_s)
+1.4770245054458029 w(Total_Fwd_Packets_Total_Backward_Packets)
+2.3767055380180433 w(Total_Fwd_Packets_Flow_Bytes_s)
+2.382865649399127 w(Total_Fwd_Packets_Flow_Packets_s)
+1.4943698678417907 w(Total_Backward_Packets_Flow_Bytes_s)
+1.4959943474349884 w(Total_Backward_Packets_Flow_Packets_s)
+2.413622112981884 w(Flow_Bytes_s_Flow_Packets_s)

s.t.

c_l_constraint_min_features_:
+1 z(Flow_Duration)
+1 z(Total_Fwd_Packets)
+1 z(Total_Backward_Packets)
+1 z(Flow_Bytes_s)
+1 z(Flow_Packets_s)
>= 3

c_u_constraint_max_features_:
+1 z(Flow_Duration)
+1 z(Total_Fwd_Packets)
+1 z(Total_Backward_Packets)
+1 z(Flow_Bytes_s)
+1 z(Flow_Packets_s)
<= 4

c_u_constraint_linearize(Flow_Duration_Total_Fwd_Packets)_:
+1 z(Flow_Duration)
+1 z(Total_Fwd_Packets)
-1 w(Flow_Duration_Total_Fwd_Packets)
<= 1.0

c_u_constraint_linearize(Flow_Duration_Total_Backward_Packets)_:
+1 z(Flow_Duration)
+1 z(Total_Backward_Packets)
-1 w(Flow_Duration_Total_Backward_Packets)
<= 1.0

c_u_constraint_linearize(Flow_Duration_Flow_Bytes_s)_:
+1 z(Flow_Duration)
+1 z(Flow_Bytes_s)
-1 w(Flow_Duration_Flow_Bytes_s)
<= 1.0

c_u_constraint_linearize(Flow_Duration_Flow_Packets_s)_:
+1 z(Flow_Duration)
+1 z(Flow_Packets_s)
-1 w(Flow_Duration_Flow_Packets_s)
<= 1.0

c_u_constraint_linearize(Total_Fwd_Packets_Total_Backward_Packets)_:
+1 z(Total_Fwd_Packets)
+1 z(Total_Backward_Packets)
-1 w(Total_Fwd_Packets_Total_Backward_Packets)
<= 1.0

c_u_constraint_linearize(Total_Fwd_Packets_Flow_Bytes_s)_:
+1 z(Total_Fwd_Packets)
+1 z(Flow_Bytes_s)
-1 w(Total_Fwd_Packets_Flow_Bytes_s)
<= 1.0

c_u_constraint_linearize(Total_Fwd_Packets_Flow_Packets_s)_:
+1 z(Total_Fwd_Packets)
+1 z(Flow_Packets_s)
-1 w(Total_Fwd_Packets_Flow_Packets_s)
<= 1.0

c_u_constraint_linearize(Total_Backward_Packets_Flow_Bytes_s)_:
+1 z(Total_Backward_Packets)
+1 z(Flow_Bytes_s)
-1 w(Total_Backward_Packets_Flow_Bytes_s)
<= 1.0

c_u_constraint_linearize(Total_Backward_Packets_Flow_Packets_s)_:
+1 z(Total_Backward_Packets)
+1 z(Flow_Packets_s)
-1 w(Total_Backward_Packets_Flow_Packets_s)
<= 1.0

c_u_constraint_linearize(Flow_Bytes_s_Flow_Packets_s)_:
+1 z(Flow_Bytes_s)
+1 z(Flow_Packets_s)
-1 w(Flow_Bytes_s_Flow_Packets_s)
<= 1.0

c_u_constraint_dep_Flow_Bytes_s_:
-1 z(Flow_Duration)
+1 z(Flow_Bytes_s)
<= 0

c_u_constraint_dep_Flow_Packets_s_:
-1 z(Flow_Duration)
+1 z(Flow_Packets_s)
<= 0

bounds
   0 <= z(Flow_Duration) <= 1
   0 <= z(Total_Fwd_Packets) <= 1
   0 <= z(Total_Backward_Packets) <= 1
   0 <= z(Flow_Bytes_s) <= 1
   0 <= z(Flow_Packets_s) <= 1
   0 <= w(Flow_Duration_Total_Fwd_Packets) <= 1
   0 <= w(Flow_Duration_Total_Backward_Packets) <= 1
   0 <= w(Flow_Duration_Flow_Bytes_s) <= 1
   0 <= w(Flow_Duration_Flow_Packets_s) <= 1
   0 <= w(Total_Fwd_Packets_Total_Backward_Packets) <= 1
   0 <= w(Total_Fwd_Packets_Flow_Bytes_s) <= 1
   0 <= w(Total_Fwd_Packets_Flow_Packets_s) <= 1
   0 <= w(Total_Backward_Packets_Flow_Bytes_s) <= 1
   0 <= w(Total_Backward_Packets_Flow_Packets_s) <= 1
   0 <= w(Flow_Bytes_s_Flow_Packets_s) <= 1
binary
  z(Flow_Duration)
  z(Total_Fwd_Packets)
  z(Total_Backward_Packets)
  z(Flow_Bytes_s)
  z(Flow_Packets_s)
end
