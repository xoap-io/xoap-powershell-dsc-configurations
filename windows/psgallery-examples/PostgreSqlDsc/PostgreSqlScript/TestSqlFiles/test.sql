/*SELECT EXISTS(SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'User')

SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'User'


DO
$do$
BEGIN
   IF EXISTS (SELECT FROM orders) THEN
      DELETE FROM orders;
   ELSE
      INSERT INTO orders VALUES (1,2,3);
   END IF;
END
$do$*/

DO $$
BEGIN
IF NOT exists (SELECT * FROM information_schema.tables Where table_schema = 'public' AND table_name = 'Users')
THEN RAISE INFO 'Message that is returned and causes failure.';
END IF;
END $$
