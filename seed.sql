-- OPTIONAL: demo data for testing. Skip this on a live site.
insert into reports (sector, area, hazard, description, urgency, status, created_at, updated_at)
select v.sector, v.area, v.hazard, v.description, v.urgency, v.status,
       (extract(epoch from now()) * 1000)::bigint - v.ago * 60000,
       (extract(epoch from now()) * 1000)::bigint - v.ago * 60000
from (values
  ('Environment','Lilongwe','Water contamination','Community members observed unusual colour and odour in a local water source.','Low','Open',60),
  ('Veterinary','Zomba','Livestock illness','Farmers report unusual illness affecting cattle in two nearby villages.','Medium','Investigating',41),
  ('Human Health','Blantyre','Respiratory uptick','Several households report an increase in cough and breathing-related symptoms.','Medium','Open',28),
  ('Agriculture','Lilongwe','Moldy Maize / Aflatoxin','Visible mould reported in stored maize at a community grain facility.','High','Open',12)
) as v(sector, area, hazard, description, urgency, status, ago);
