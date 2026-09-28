CREATE TABLE `backup_restore_rows` (
	`table_name` text NOT NULL,
	`position` integer NOT NULL,
	`row` text NOT NULL,
	CONSTRAINT `backup_restore_rows_pk` PRIMARY KEY(`table_name`, `position`)
);
